"""Only Us: a private, two-account shared space for Ahmed and Mahra.

Run: python server.py (Python 3.11+). See START_HERE.html before public hosting.
All private data lives outside public/. No sign-up or third-party trackers.
"""
from __future__ import annotations

import base64
import calendar
import contextlib
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import time
import tempfile
import uuid
import warnings
import zipfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from starlette.background import BackgroundTask
from PIL import Image, ImageOps, UnidentifiedImageError

BASE = Path(__file__).resolve().parent
DATA = Path(os.getenv('DATA_DIR', str(BASE / 'data'))).resolve()
PRODUCTION = os.getenv('APP_ENV', 'local') == 'production'
PUBLIC_ORIGIN = (os.getenv('PUBLIC_ORIGIN') or os.getenv('RENDER_EXTERNAL_URL', '')).rstrip('/')
SESSION_COOKIE = '__Host-onlyus' if PRODUCTION else 'onlyus_session'
MAX_PHOTO_BYTES = 12 * 1024 * 1024
MAX_STORAGE_BYTES = int(os.getenv('MAX_STORAGE_MB', '600')) * 1024 * 1024
SESSION_SECONDS = 14 * 24 * 3600
Image.MAX_IMAGE_PIXELS = 30_000_000
warnings.simplefilter('error', Image.DecompressionBombWarning)
LOG = logging.getLogger('onlyus')
CONTENT = json.loads((BASE / 'public/assets/content.json').read_text())
USERS = ('Ahmed', 'Mahra')
SCHEMA = '''
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY CHECK(id IN ('Ahmed','Mahra')),
 password_hash TEXT NOT NULL, must_change INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 csrf TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS attempts (bucket TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS attempts_lookup ON attempts(bucket, ts);
CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL);
INSERT OR IGNORE INTO meta VALUES(1,0);
CREATE TABLE IF NOT EXISTS settings (
 id INTEGER PRIMARY KEY CHECK(id=1), start_date TEXT NOT NULL DEFAULT '',
 ahmed_birthday TEXT NOT NULL DEFAULT '', mahra_birthday TEXT NOT NULL DEFAULT '',
 timezone TEXT NOT NULL DEFAULT 'Asia/Dubai', version INTEGER NOT NULL DEFAULT 1
);
INSERT OR IGNORE INTO settings(id) VALUES(1);
CREATE TABLE IF NOT EXISTS notes (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, color TEXT NOT NULL,
 pinned INTEGER NOT NULL DEFAULT 0, author TEXT NOT NULL REFERENCES users(id),
 edited_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS photos (
 id TEXT PRIMARY KEY, caption TEXT NOT NULL, moment_date TEXT NOT NULL,
 author TEXT NOT NULL REFERENCES users(id), filename TEXT NOT NULL,
 size INTEGER NOT NULL, created_at TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS tasks (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, category TEXT NOT NULL, assignee TEXT NOT NULL,
 due_date TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0,
 author TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL,
 version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS events (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, date TEXT NOT NULL, annual INTEGER NOT NULL,
 author TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL,
 version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS moods (
 day TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id), mood TEXT NOT NULL,
 message TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(day,user_id)
);
CREATE TABLE IF NOT EXISTS daily_answers (
 day TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id), answer TEXT NOT NULL,
 created_at TEXT NOT NULL, PRIMARY KEY(day,user_id)
);
CREATE TABLE IF NOT EXISTS quizzes (
 id TEXT PRIMARY KEY, author TEXT NOT NULL REFERENCES users(id), question TEXT NOT NULL,
 options TEXT NOT NULL, correct INTEGER NOT NULL CHECK(correct BETWEEN 0 AND 3),
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS quiz_answers (
 quiz_id TEXT NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id), choice INTEGER NOT NULL,
 is_correct INTEGER NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(quiz_id,user_id)
);
CREATE TABLE IF NOT EXISTS game (
 id INTEGER PRIMARY KEY CHECK(id=1), board TEXT NOT NULL,
 turn TEXT NOT NULL, winner TEXT, round INTEGER NOT NULL, version INTEGER NOT NULL
);
INSERT OR IGNORE INTO game VALUES(1,'[null,null,null,null,null,null,null,null,null]','Ahmed',NULL,1,1);
CREATE TABLE IF NOT EXISTS game_results (
 round INTEGER PRIMARY KEY, winner TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memory_scores (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), moves INTEGER NOT NULL,
 seconds INTEGER NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS favorites (
 user_id TEXT NOT NULL REFERENCES users(id), joke_id INTEGER NOT NULL, PRIMARY KEY(user_id,joke_id)
);
CREATE TABLE IF NOT EXISTS hugs (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
);
'''


class AppError(Exception):
    def __init__(self, message: str, status: int = 400):
        self.message, self.status = message, status


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def uid() -> str:
    return uuid.uuid4().hex


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=32768, r=8, p=1, maxmem=64*1024*1024)
    return 'scrypt$32768$8$1$' + salt.hex() + '$' + derived.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, n, r, p, salt, digest = stored.split('$')
        if algorithm != 'scrypt' or (n, r, p) != ('32768', '8', '1'):
            return False
        actual = hash_password(password, bytes.fromhex(salt)).split('$')[-1]
        return hmac.compare_digest(actual, digest)
    except (ValueError, TypeError):
        return False


@contextlib.contextmanager
def db(write: bool = False):
    con = sqlite3.connect(DATA / 'only-us.sqlite3', timeout=15)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    con.execute('PRAGMA busy_timeout=15000')
    try:
        con.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        yield con
        con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()


def initialize() -> None:
    DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
    (DATA / 'photos').mkdir(mode=0o700, exist_ok=True)
    with sqlite3.connect(DATA / 'only-us.sqlite3') as con:
        con.executescript(SCHEMA)
    with db(True) as con:
        if con.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
            bootstrap = BASE / '.bootstrap-users.json'
            seeds = json.loads(bootstrap.read_text()) if bootstrap.exists() and not PRODUCTION else {}
            for user in USERS:
                password = os.getenv(user.upper() + '_INITIAL_PASSWORD')
                if password:
                    if PRODUCTION and len(password) < 12:
                        raise RuntimeError(f'{user.upper()}_INITIAL_PASSWORD must have at least 12 characters in production.')
                    stored = hash_password(password)
                else:
                    stored = seeds.get(user)
                if not stored:
                    raise RuntimeError(f'Set {user.upper()}_INITIAL_PASSWORD before first start. See START_HERE.html.')
                con.execute('INSERT INTO users VALUES(?,?,1)', (user, stored))
        con.execute('DELETE FROM sessions WHERE expires<?', (int(time.time()),))
    if PRODUCTION and not (PUBLIC_ORIGIN.startswith('https://') and '/' not in PUBLIC_ORIGIN[8:]):
        raise RuntimeError('Production needs PUBLIC_ORIGIN=https://your-hostname (no trailing path).')


def change(con) -> None:
    con.execute('UPDATE meta SET revision=revision+1 WHERE id=1')


def text(data: dict, key: str, maximum: int, required: bool = True) -> str:
    v = data.get(key, '')
    if not isinstance(v, str):
        raise AppError(f'{key.replace("_", " ").capitalize()} must be text.')
    v = v.strip()
    if required and not v:
        raise AppError(f'Please enter {key.replace("_", " ")}.')
    if len(v) > maximum:
        raise AppError(f'{key.replace("_", " ").capitalize()} is too long (maximum {maximum}).')
    return v


def integer(data: dict, key: str, low: int, high: int) -> int:
    v = data.get(key)
    if type(v) is not int or not low <= v <= high:
        raise AppError(f'Invalid {key}.')
    return v


def boolean(data: dict, key: str) -> int:
    if data.get(key) not in (True, False, 0, 1):
        raise AppError(f'Invalid {key}.')
    return int(bool(data.get(key)))


def date_value(data: dict, key: str, required: bool = False) -> str:
    value = text(data, key, 10, required)
    if value:
        try:
            if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', value):
                raise ValueError()
            parsed = date.fromisoformat(value)
            if not 1900 <= parsed.year <= 2200:
                raise ValueError()
        except ValueError:
            raise AppError(f'Choose a valid {key.replace("_", " ")} between 1900 and 2200.')
    return value


def password_value(data: dict, key: str = 'password') -> str:
    v = data.get(key)
    if not isinstance(v, str) or not 1 <= len(v) <= 256:
        raise AppError('Please enter a password (maximum 256 characters).')
    return v  # Spaces matter. Never strip a password.


def settings_row(con) -> dict:
    return dict(con.execute('SELECT * FROM settings WHERE id=1').fetchone())


def local_day(con) -> date:
    return datetime.now(ZoneInfo(settings_row(con)['timezone'])).date()


def limited(con, bucket: str, limit: int, window: int = 900) -> None:
    now = int(time.time())
    con.execute('DELETE FROM attempts WHERE ts<?', (now - 86400,))
    count = con.execute('SELECT COUNT(*) FROM attempts WHERE bucket=? AND ts>?', (bucket, now-window)).fetchone()[0]
    if count >= limit:
        raise AppError('Too many attempts. Please try again later.', 429)
    con.execute('INSERT INTO attempts VALUES(?,?)', (bucket, now))


def login_attempt(ip: str, user: str) -> None:
    # A separate committed transaction makes failed attempts survive request rollback.
    with db(True) as con:
        limited(con, 'login-ip:' + ip, 40)
        limited(con, 'login-user:' + user, 12)


def session_for(con, cookie: str | None) -> dict | None:
    if not cookie or len(cookie) > 200:
        return None
    token_hash = hashlib.sha256(cookie.encode()).hexdigest()
    row = con.execute('SELECT s.*, u.must_change FROM sessions s JOIN users u ON u.id=s.user_id WHERE token_hash=? AND expires>?', (token_hash, int(time.time()))).fetchone()
    return dict(row) if row else None


def session_response(session: dict | None) -> dict:
    if not session:
        return {'user': None, 'csrf': None}
    return {'user': session['user_id'], 'csrf': session['csrf'], 'must_change': bool(session['must_change'])}


def require_version(row: dict, data: dict) -> None:
    if type(data.get('version')) is not int or row['version'] != data['version']:
        raise AppError('This changed on the other device. Close this form, refresh, and try again.', 409)


def item(con, table: str, identifier: str) -> dict:
    assert table in {'notes', 'photos', 'tasks', 'events', 'quizzes'}
    row = con.execute(f'SELECT * FROM {table} WHERE id=?', (identifier,)).fetchone()
    if not row:
        raise AppError('That item no longer exists.', 404)
    return dict(row)


def annual_occurrence(original: str, today: date) -> date:
    d = date.fromisoformat(original)
    day = min(d.day, calendar.monthrange(today.year, d.month)[1])
    result = date(today.year, d.month, day)
    if result < today:
        year = today.year + 1
        result = date(year, d.month, min(d.day, calendar.monthrange(year, d.month)[1]))
    return result


def event_list(con) -> list[dict]:
    today, settings = local_day(con), settings_row(con)
    rows = [dict(r) for r in con.execute('SELECT * FROM events')]
    for key, title in [('ahmed_birthday', "Ahmed's birthday"), ('mahra_birthday', "Mahra's birthday"), ('start_date', 'Our anniversary')]:
        if settings[key]:
            rows.append({'id': key, 'title': title, 'date': settings[key], 'annual': 1, 'system': True, 'version': 1})
    for r in rows:
        nxt = annual_occurrence(r['date'], today) if r['annual'] else date.fromisoformat(r['date'])
        r['next_date'], r['days_left'] = nxt.isoformat(), (nxt - today).days
    return sorted(rows, key=lambda r: (r['days_left'] < 0, r['next_date']))


def snapshot(con, user: str) -> dict:
    settings = settings_row(con)
    today = local_day(con).isoformat()
    start = settings['start_date']
    settings['start_at'] = datetime.combine(date.fromisoformat(start), datetime.min.time(), ZoneInfo(settings['timezone'])).isoformat() if start else None
    quizzes = []
    for r in con.execute('SELECT * FROM quizzes ORDER BY created_at DESC, id DESC'):
        q = dict(r)
        q['options'] = json.loads(q['options'])
        answers = [dict(a) for a in con.execute('SELECT * FROM quiz_answers WHERE quiz_id=?', (q['id'],))]
        mine = next((a for a in answers if a['user_id'] == user), None)
        q['answers'] = answers if user == q['author'] else ([mine] if mine else [])
        q['my_answer'] = mine
        if user != q['author'] and mine is None:
            q.pop('correct')  # The browser never receives an unrevealed answer.
        quizzes.append(q)
    daily = [dict(a) for a in con.execute('SELECT * FROM daily_answers WHERE day=?', (today,))]
    revealed = len(daily) == 2
    game = dict(con.execute('SELECT * FROM game WHERE id=1').fetchone())
    game['board'] = json.loads(game['board'])
    game_stats = {r['winner']: r['n'] for r in con.execute('SELECT winner,COUNT(*) n FROM game_results GROUP BY winner')}
    photos = [dict(r) for r in con.execute('SELECT id,caption,moment_date,author,size,created_at,version FROM photos ORDER BY created_at DESC,id DESC')]
    return {
        'revision': str(con.execute('SELECT revision FROM meta WHERE id=1').fetchone()[0]) + ':' + today,
        'server_now': now_iso(), 'today': today, 'settings': settings,
        'notes': [dict(r) for r in con.execute('SELECT * FROM notes ORDER BY pinned DESC,updated_at DESC,id DESC')],
        'photos': photos,
        'tasks': [dict(r) for r in con.execute('SELECT * FROM tasks ORDER BY done,created_at DESC,id DESC')],
        'events': event_list(con),
        'moods': [dict(r) for r in con.execute('SELECT * FROM moods WHERE day=?', (today,))],
        'daily': {'question': CONTENT['questions'][date.fromisoformat(today).toordinal() % len(CONTENT['questions'])],
                  'revealed': revealed, 'answered_by': [a['user_id'] for a in daily],
                  'answers': daily if revealed else [a for a in daily if a['user_id'] == user]},
        'quizzes': quizzes, 'game': game, 'game_stats': game_stats,
        'memory_scores': [dict(r) for r in con.execute('SELECT * FROM memory_scores ORDER BY moves,seconds LIMIT 10')],
        'favorites': [r[0] for r in con.execute('SELECT joke_id FROM favorites WHERE user_id=?', (user,))],
        'hugs': [dict(r) for r in con.execute('SELECT * FROM hugs ORDER BY created_at DESC,id DESC LIMIT 6')],
        'hug_count': con.execute('SELECT COUNT(*) FROM hugs').fetchone()[0],
        'storage_used': con.execute('SELECT COALESCE(SUM(size),0) FROM photos').fetchone()[0],
        'storage_limit': MAX_STORAGE_BYTES,
    }


def save_photo(con, user: str, body: dict) -> str:
    caption = text(body, 'caption', 500, False)
    moment_date = date_value(body, 'moment_date')
    raw = body.get('image', '')
    if not isinstance(raw, str) or not raw.startswith('data:') or ',' not in raw or len(raw) > MAX_PHOTO_BYTES*1.4:
        raise AppError('Choose a JPG, PNG, or WebP photo smaller than 12 MB.')
    try:
        decoded = base64.b64decode(raw.split(',', 1)[1], validate=True)
        if len(decoded) > MAX_PHOTO_BYTES:
            raise AppError('Photo must be smaller than 12 MB.', 413)
        with Image.open(io.BytesIO(decoded)) as im:
            if im.format not in ('JPEG', 'PNG', 'WEBP'):
                raise AppError('Supported formats are JPG, PNG, and WebP. Convert HEIC photos first.')
            im.load()
            im = ImageOps.exif_transpose(im).convert('RGB')
            im.thumbnail((2560, 2560), Image.Resampling.LANCZOS)
            # Copy pixels into a fresh image to discard EXIF/GPS and other metadata.
            clean = Image.new('RGB', im.size)
            clean.paste(im)
            output = io.BytesIO()
            clean.save(output, format='WEBP', quality=88, method=4)
            encoded = output.getvalue()
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise AppError('This photo cannot be safely read. Try a smaller JPG, PNG, or WebP.')
    total = con.execute('SELECT COALESCE(SUM(size),0), COUNT(*) FROM photos').fetchone()
    if total[0]+len(encoded) > MAX_STORAGE_BYTES or total[1] >= 500:
        raise AppError('Your photo space is full. Export a backup and remove some photos.', 413)
    identifier = uid()
    target = DATA / 'photos' / (identifier + '.webp')
    target.write_bytes(encoded)
    try:
        con.execute('INSERT INTO photos VALUES(?,?,?,?,?,?,?,1)', (identifier, caption, moment_date, user, target.name, len(encoded), now_iso()))
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return identifier


def calendar_bytes(events: list[dict]) -> bytes:
    def escape(s):
        return s.replace('\\', '\\\\').replace('\n', '\\n').replace(';', '\\;').replace(',', '\\,')
    lines = ['BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//Only Us//Shared Moments//EN','CALSCALE:GREGORIAN','METHOD:PUBLISH']
    for e in events:
        # Explicit upcoming occurrence: this also handles Feb 29 on non-leap years.
        day = date.fromisoformat(e['next_date'])
        lines += ['BEGIN:VEVENT', f"UID:onlyus-{e['id']}-{day.year}@private.local", 'DTSTAMP:'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'),
                  'DTSTART;VALUE=DATE:'+day.strftime('%Y%m%d'), 'DTEND;VALUE=DATE:'+(day+timedelta(days=1)).strftime('%Y%m%d'),
                  'SUMMARY:'+escape(e['title']), 'DESCRIPTION:From Only Us. Re-export each year for recurring occasions.']
        for trigger in ('-P7D', '-P1D'):
            lines += ['BEGIN:VALARM','ACTION:DISPLAY','DESCRIPTION:'+escape(e['title']),'TRIGGER:'+trigger,'END:VALARM']
        lines += ['END:VEVENT']
    lines += ['END:VCALENDAR']
    # Fold by UTF-8 bytes (RFC 5545), never splitting a multibyte code point.
    folded = []
    for line in lines:
        part = ''
        for char in line:
            if len((part+char).encode()) > 73:
                folded.append(part)
                part = ' '
            part += char
        folded.append(part)
    return ('\r\n'.join(folded)+'\r\n').encode('utf-8')


def dispatch(method: str, path: str, body: dict, cookie: str | None, csrf: str, ip: str) -> Response:
    if path == 'login' and method == 'POST':
        username = text(body, 'username', 80).casefold()
        user = next((u for u in USERS if u.casefold() == username), '')
        password = password_value(body)
        login_attempt(ip, user or 'unknown')
        with db(True) as con:
            r = con.execute('SELECT * FROM users WHERE id=?', (user,)).fetchone()
            # Use a real hash even for unknown usernames to reduce timing differences.
            fallback = con.execute('SELECT password_hash FROM users LIMIT 1').fetchone()[0]
            valid = verify_password(password, r['password_hash'] if r else fallback)
            if not r or not valid:
                raise AppError('That username or password is not right.', 401)
            token, csrf_token = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
            con.execute('DELETE FROM sessions WHERE expires<?', (int(time.time()),))
            if cookie:
                con.execute('DELETE FROM sessions WHERE token_hash=?', (hashlib.sha256(cookie.encode()).hexdigest(),))
            con.execute('INSERT INTO sessions VALUES(?,?,?,?)', (hashlib.sha256(token.encode()).hexdigest(), user, csrf_token, int(time.time())+SESSION_SECONDS))
            con.execute('DELETE FROM attempts WHERE bucket=?', ('login-user:'+user,))
            response = JSONResponse({'user': user, 'csrf': csrf_token, 'must_change': bool(r['must_change'])})
            response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_SECONDS, httponly=True, secure=PRODUCTION, samesite='strict', path='/')
            return response

    if path in ('password', 'backup') and method == 'POST':
        with db(True) as rate_con:
            limited(rate_con, 'sensitive-ip:' + ip, 10, 900)
    write = method != 'GET'
    with db(write) as con:
        session = session_for(con, cookie)
        if path == 'session' and method == 'GET':
            return JSONResponse(session_response(session))
        if not session:
            raise AppError('Please sign in to your space.', 401)
        user = session['user_id']
        if write and not hmac.compare_digest(csrf, session['csrf']):
            raise AppError('Your session changed. Refresh and try again.', 403)
        if path == 'logout' and method == 'POST':
            con.execute('DELETE FROM sessions WHERE token_hash=?', (session['token_hash'],))
            response = JSONResponse({'ok': True})
            response.delete_cookie(SESSION_COOKIE, httponly=True, secure=PRODUCTION, samesite='strict', path='/')
            return response
        if path == 'password' and method == 'POST':
            stored = con.execute('SELECT password_hash FROM users WHERE id=?', (user,)).fetchone()[0]
            old, new = password_value(body, 'current_password'), password_value(body, 'new_password')
            if not verify_password(old, stored):
                raise AppError('Your current password is not right.', 400)
            if len(new) < 12 or new == old:
                raise AppError('Choose a different password with at least 12 characters.')
            con.execute('UPDATE users SET password_hash=?,must_change=0 WHERE id=?', (hash_password(new), user))
            con.execute('DELETE FROM sessions WHERE user_id=? AND token_hash<>?', (user, session['token_hash']))
            change(con)
            return JSONResponse({'ok': True})
        if session['must_change']:
            raise AppError('Please set a new private password first.', 428)
        if path == 'state' and method == 'GET':
            return JSONResponse(snapshot(con, user))
        parts = path.split('/')
        table = parts[0]
        identifier = parts[1] if len(parts) > 1 else ''
        if table == 'photos' and len(parts) == 3 and parts[2] == 'image' and method == 'GET':
            photo = item(con, 'photos', identifier)
            target = DATA / 'photos' / photo['filename']
            if not target.exists():
                raise AppError('Photo file is unavailable. Restore from your backup.', 404)
            return FileResponse(target, media_type='image/webp', headers={'Cache-Control':'no-store, private'})
        if path == 'calendar' and method == 'GET':
            events = [e for e in event_list(con) if e['days_left'] >= 0]
            return Response(calendar_bytes(events), media_type='text/calendar', headers={'Content-Disposition':'attachment; filename="our-dates.ics"'})
        if path == 'backup' and method == 'POST':
            stored = con.execute('SELECT password_hash FROM users WHERE id=?', (user,)).fetchone()[0]
            if not verify_password(password_value(body), stored):
                raise AppError('Your password is not right.', 400)
            handle = tempfile.NamedTemporaryFile(prefix='onlyus-export-', suffix='.zip', delete=False)
            output_path = Path(handle.name)
            handle.close()
            try:
                with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as archive:
                    # Stream photos to a temporary archive, not a potentially huge RAM buffer.
                    archive.writestr('shared-data.json', json.dumps(snapshot(con, user), indent=2, ensure_ascii=False))
                    archive.writestr('README.txt', 'Personal data export from Only Us. Keep private. No passwords or sessions. Photos are optimized, metadata-stripped copies. Unrevealed partner answers are omitted. For a full restorable administrator backup, use manage.py backup.\n')
                    for r in con.execute('SELECT id,filename FROM photos'):
                        file = DATA / 'photos' / r['filename']
                        if file.exists():
                            archive.write(file, 'photos/'+r['filename'])
                return FileResponse(output_path, media_type='application/zip', filename='only-us-export.zip', background=BackgroundTask(output_path.unlink, missing_ok=True))
            except Exception:
                output_path.unlink(missing_ok=True)
                raise
        if path == 'settings' and method == 'PATCH':
            previous = settings_row(con)
            require_version(previous, body)
            tz = text(body, 'timezone', 80)
            try:
                zone = ZoneInfo(tz)
            except ZoneInfoNotFoundError:
                raise AppError('Choose a valid timezone, such as Asia/Dubai.')
            dates = [date_value(body, key) for key in ('start_date','ahmed_birthday','mahra_birthday')]
            today = datetime.now(zone).date().isoformat()
            if any(d and d > today for d in dates):
                raise AppError('Relationship start and birth dates cannot be in the future.')
            con.execute('UPDATE settings SET start_date=?,ahmed_birthday=?,mahra_birthday=?,timezone=?,version=version+1 WHERE id=1', (*dates, tz))
        elif table == 'notes' and method == 'POST' and not identifier:
            if con.execute('SELECT COUNT(*) FROM notes').fetchone()[0] >= 1000:
                raise AppError('Your board is full. Export and remove some notes.')
            title, note_body = text(body,'title',100,False), text(body,'body',8000)
            color = text(body,'color',20)
            if color not in ('rose','sage','butter','lavender'):
                raise AppError('Choose a note color.')
            identifier = uid()
            con.execute('INSERT INTO notes VALUES(?,?,?,?,?,?,?,?,?,1)', (identifier, title, note_body, color, 0, user, user, now_iso(), now_iso()))
        elif table == 'notes' and method == 'PATCH' and identifier:
            old = item(con, table, identifier)
            require_version(old, body)
            if set(body) <= {'version','pinned'}:
                con.execute('UPDATE notes SET pinned=?,version=version+1 WHERE id=?', (boolean(body,'pinned'), identifier))
            else:
                title, note_body = text(body,'title',100,False), text(body,'body',8000)
                color = text(body,'color',20)
                if color not in ('rose','sage','butter','lavender'):
                    raise AppError('Choose a note color.')
                con.execute('UPDATE notes SET title=?,body=?,color=?,edited_by=?,updated_at=?,version=version+1 WHERE id=?', (title,note_body,color,user,now_iso(),identifier))
        elif table == 'photos' and method == 'POST' and not identifier:
            identifier = save_photo(con, user, body)
        elif table == 'photos' and method == 'PATCH' and identifier:
            old = item(con,table,identifier)
            require_version(old,body)
            con.execute('UPDATE photos SET caption=?,moment_date=?,version=version+1 WHERE id=?', (text(body,'caption',500,False),date_value(body,'moment_date'),identifier))
        elif table == 'tasks' and method == 'POST' and not identifier:
            title = text(body,'title',180)
            category, assignee = body.get('category'), body.get('assignee')
            if category not in ('adventure','todo','wishlist') or assignee not in ('Both',*USERS):
                raise AppError('Choose a category and who it is for.')
            if con.execute('SELECT COUNT(*) FROM tasks').fetchone()[0] >= 1000:
                raise AppError('Your plans list is full.')
            identifier = uid()
            con.execute('INSERT INTO tasks VALUES(?,?,?,?,?,0,?,?,1)', (identifier,title,category,assignee,date_value(body,'due_date'),user,now_iso()))
        elif table == 'tasks' and method == 'PATCH' and identifier:
            old = item(con,table,identifier)
            require_version(old,body)
            con.execute('UPDATE tasks SET done=?,version=version+1 WHERE id=?', (boolean(body,'done'),identifier))
        elif table == 'events' and method == 'POST' and not identifier:
            if con.execute('SELECT COUNT(*) FROM events').fetchone()[0] >= 300:
                raise AppError('Your calendar is full.')
            identifier = uid()
            con.execute('INSERT INTO events VALUES(?,?,?,?,?,?,1)', (identifier,text(body,'title',120),date_value(body,'date',True),boolean(body,'annual'),user,now_iso()))
        elif table in ('notes','photos','tasks','events','quizzes') and method == 'DELETE' and identifier:
            old = item(con, table, identifier)
            if table == 'quizzes' and old['author'] != user:
                raise AppError('Only the person who wrote a quiz can delete it.',403)
            if table != 'quizzes':
                require_version(old,body)
            con.execute(f'DELETE FROM {table} WHERE id=?', (identifier,))
            if table == 'photos':
                (DATA / 'photos' / old['filename']).unlink(missing_ok=True)
        elif path == 'mood' and method == 'POST':
            mood = text(body,'mood',30)
            if mood not in ('sunny','okay','low','hug','missing'):
                raise AppError('Choose a mood.')
            con.execute('INSERT INTO moods VALUES(?,?,?,?,?) ON CONFLICT(day,user_id) DO UPDATE SET mood=excluded.mood,message=excluded.message,updated_at=excluded.updated_at', (local_day(con).isoformat(),user,mood,text(body,'message',240,False),now_iso()))
        elif path == 'daily' and method == 'POST':
            today = local_day(con).isoformat()
            if text(body,'day',10) != today:
                raise AppError('A new day has started. Refresh to answer the new question.',409)
            if con.execute('SELECT COUNT(*) FROM daily_answers WHERE day=?', (today,)).fetchone()[0] == 2:
                raise AppError('Both answers are revealed. A fresh question arrives tomorrow.',409)
            con.execute('INSERT INTO daily_answers VALUES(?,?,?,?) ON CONFLICT(day,user_id) DO UPDATE SET answer=excluded.answer,created_at=excluded.created_at', (today,user,text(body,'answer',1500),now_iso()))
        elif table == 'quizzes' and method == 'POST' and not identifier:
            question = text(body,'question',250)
            options = body.get('options')
            if not isinstance(options,list) or len(options)!=4 or any(not isinstance(o,str) or not o.strip() or len(o)>150 for o in options):
                raise AppError('Enter four answer options, up to 150 characters each.')
            options = [o.strip() for o in options]
            if len({o.casefold() for o in options}) != 4:
                raise AppError('Make the four answer options different.')
            correct = integer(body,'correct',0,3)
            if con.execute('SELECT COUNT(*) FROM quizzes').fetchone()[0] >= 500:
                raise AppError('Your quiz collection is full.')
            identifier = uid()
            con.execute('INSERT INTO quizzes VALUES(?,?,?,?,?,?)', (identifier,user,question,json.dumps(options),correct,now_iso()))
        elif table == 'quizzes' and len(parts)==3 and parts[2]=='answer' and method=='POST':
            q = item(con,'quizzes',identifier)
            if q['author'] == user:
                raise AppError('This question is for your partner.')
            choice = integer(body,'choice',0,3)
            if con.execute('SELECT 1 FROM quiz_answers WHERE quiz_id=? AND user_id=?',(identifier,user)).fetchone():
                raise AppError('You already answered this question.',409)
            con.execute('INSERT INTO quiz_answers VALUES(?,?,?,?,?)',(identifier,user,choice,int(choice==q['correct']),now_iso()))
        elif path == 'game/move' and method=='POST':
            game = dict(con.execute('SELECT * FROM game WHERE id=1').fetchone())
            require_version(game,body)
            board = json.loads(game['board'])
            cell = integer(body,'cell',0,8)
            if game['winner']:
                raise AppError('This round is finished. Start a new one.')
            if game['turn'] != user:
                raise AppError('It is your partner\'s turn.',409)
            if board[cell] is not None:
                raise AppError('That square is already taken.',409)
            board[cell] = user
            lines = [(0,1,2),(3,4,5),(6,7,8),(0,3,6),(1,4,7),(2,5,8),(0,4,8),(2,4,6)]
            winner = user if any(all(board[i]==user for i in line) for line in lines) else ('draw' if all(board) else None)
            turn = 'Mahra' if user=='Ahmed' else 'Ahmed'
            con.execute('UPDATE game SET board=?,turn=?,winner=?,version=version+1 WHERE id=1',(json.dumps(board),turn,winner))
            if winner:
                con.execute('INSERT INTO game_results VALUES(?,?,?)',(game['round'],winner,now_iso()))
        elif path == 'game/reset' and method=='POST':
            game = dict(con.execute('SELECT * FROM game WHERE id=1').fetchone())
            require_version(game,body)
            rnd = game['round']+1
            con.execute('UPDATE game SET board=?,turn=?,winner=NULL,round=?,version=version+1 WHERE id=1',(json.dumps([None]*9),'Ahmed' if rnd%2 else 'Mahra',rnd))
        elif path=='memory' and method=='POST':
            moves, seconds = integer(body,'moves',6,10000),integer(body,'seconds',1,86400)
            con.execute('INSERT INTO memory_scores VALUES(?,?,?,?,?)',(uid(),user,moves,seconds,now_iso()))
            con.execute('DELETE FROM memory_scores WHERE id NOT IN (SELECT id FROM memory_scores ORDER BY moves,seconds LIMIT 100)')
        elif path=='favorite' and method=='POST':
            joke_id = integer(body,'joke_id',0,len(CONTENT['jokes'])-1)
            con.execute('DELETE FROM favorites WHERE user_id=? AND joke_id=?',(user,joke_id)) if body.get('remove') else con.execute('INSERT OR IGNORE INTO favorites VALUES(?,?)',(user,joke_id))
        elif path=='hug' and method=='POST':
            last = con.execute('SELECT created_at FROM hugs WHERE user_id=? ORDER BY created_at DESC LIMIT 1',(user,)).fetchone()
            if last and (datetime.now(timezone.utc)-datetime.fromisoformat(last[0])).total_seconds()<10:
                raise AppError('That hug is still on its way. Give it a moment.',429)
            con.execute('INSERT INTO hugs VALUES(?,?,?)',(uid(),user,now_iso()))
        else:
            raise AppError('That action is not available.',404)
        change(con)
        return JSONResponse({'ok': True, 'id': identifier or None})


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    await run_in_threadpool(initialize)
    yield


app = FastAPI(title='Only Us', docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


@app.middleware('http')
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    response.headers['X-Robots-Tag'] = 'noindex, nofollow, noarchive'
    if request.url.path.startswith('/api/') or request.url.path == '/':
        response.headers['Cache-Control'] = 'no-store, private'
    if PRODUCTION:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return response


@app.api_route('/api/{path:path}', methods=['GET','POST','PATCH','DELETE'])
async def api(request: Request, path: str):
    try:
        body: dict = {}
        if request.method != 'GET':
            origin = request.headers.get('origin')
            expected = PUBLIC_ORIGIN if PRODUCTION else str(request.base_url).rstrip('/')
            if (origin and origin != expected) or request.headers.get('sec-fetch-site') == 'cross-site':
                raise AppError('Cross-site requests are not allowed.',403)
            if not request.headers.get('content-type','').lower().startswith('application/json'):
                raise AppError('Send JSON for this action.',415)
            if request.headers.get('x-only-us') != '1':
                raise AppError('Missing request header.',403)
            limit = 17*1024*1024 if path=='photos' else 64*1024
            raw = bytearray()
            async for chunk in request.stream():
                raw.extend(chunk)
                if len(raw)>limit:
                    raise AppError('This upload or message is too large.',413)
            try:
                body = json.loads(raw or b'{}')
            except (ValueError, UnicodeDecodeError):
                raise AppError('Invalid JSON.')
            if not isinstance(body,dict):
                raise AppError('A JSON object is required.')
        return await run_in_threadpool(dispatch, request.method, path, body, request.cookies.get(SESSION_COOKIE), request.headers.get('x-csrf-token',''), request.client.host if request.client else 'unknown')
    except AppError as exc:
        return JSONResponse({'error':exc.message},status_code=exc.status)
    except sqlite3.OperationalError:
        LOG.exception('Database unavailable')
        return JSONResponse({'error':'Storage is busy or unavailable. Please try again.'},status_code=503)
    except Exception:
        LOG.exception('Request failed')
        return JSONResponse({'error':'Something went wrong on the server. Please try again.'},status_code=500)


@app.get('/healthz')
def healthz():
    return {'status':'ok'}


@app.get('/')
def index():
    return FileResponse(BASE/'public/index.html')


@app.get('/manifest.webmanifest')
def manifest():
    return FileResponse(BASE/'public/manifest.webmanifest',media_type='application/manifest+json')


@app.get('/sw.js')
def service_worker():
    return FileResponse(BASE/'public/sw.js',media_type='application/javascript',headers={'Cache-Control':'no-cache'})


@app.get('/robots.txt')
def robots():
    return Response('User-agent: *\nDisallow: /\n',media_type='text/plain')


app.mount('/assets',StaticFiles(directory=BASE/'public/assets'),name='assets')

if __name__ == '__main__':
    import uvicorn
    if os.getenv('OPEN_BROWSER') == '1' and not PRODUCTION:
        import threading, webbrowser
        threading.Timer(2, lambda: webbrowser.open('http://127.0.0.1:' + os.getenv('PORT','8000'))).start()
    host = os.getenv('HOST','0.0.0.0' if PRODUCTION else '127.0.0.1')
    uvicorn.run('server:app', host=host, port=int(os.getenv('PORT','8000')), workers=1,
                proxy_headers=os.getenv('TRUST_PROXY','0')=='1',
                forwarded_allow_ips=os.getenv('FORWARDED_ALLOW_IPS','127.0.0.1'),
                limit_concurrency=32, timeout_keep_alive=5, access_log=False)
