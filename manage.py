"""Operator-only backup, restore, and password recovery. Never exposed over HTTP."""
from __future__ import annotations
import argparse
import getpass
import json
import re
import sqlite3
import tempfile
import zipfile
from pathlib import Path
import server


def backup(destination: Path) -> None:
    database = server.DATA / 'only-us.sqlite3'
    if not database.exists():
        raise SystemExit('No database found. Check DATA_DIR or start the app once.')
    if destination.exists():
        raise SystemExit('Destination already exists; choose a new filename.')
    with tempfile.TemporaryDirectory() as temp:
        copied = Path(temp)/'only-us.sqlite3'
        with sqlite3.connect(database) as original, sqlite3.connect(copied) as copy:
            original.backup(copy)
            copy.execute('DELETE FROM sessions')
            copy.commit()
            photos = copy.execute('SELECT filename FROM photos').fetchall()
        for (name,) in photos:
            if not (server.DATA/'photos'/name).is_file():
                raise SystemExit('A referenced photo is missing. Restore it before making a complete backup.')
        with zipfile.ZipFile(destination,'w',zipfile.ZIP_DEFLATED) as archive:
            archive.write(copied,'only-us.sqlite3')
            archive.writestr('manifest.json',json.dumps({'application':'Only Us','schema':1,'created_at':server.now_iso(),'contains_password_hashes':True,'contains_sessions':False}))
            for (name,) in photos:
                archive.write(server.DATA/'photos'/name,'photos/'+name)
    print(f'Backup saved to {destination.resolve()}. This contains private data and password hashes. Keep it encrypted and private.')


def restore(source: Path, destination: Path) -> None:
    if destination.exists() and any(destination.iterdir()):
        raise SystemExit('Restore target must be a new or empty directory. Your current data will not be overwritten.')
    with zipfile.ZipFile(source) as archive:
        infos=archive.infolist()
        names=[i.filename for i in infos]
        if len(names)!=len(set(names)) or sum(i.file_size for i in infos)>1024*1024*1024:
            raise SystemExit('Invalid or oversized backup.')
        if 'only-us.sqlite3' not in names or 'manifest.json' not in names:
            raise SystemExit('Use an operator backup made with manage.py, not the in-app export.')
        manifest=json.loads(archive.read('manifest.json'))
        if manifest.get('application')!='Only Us' or manifest.get('schema')!=1:
            raise SystemExit('Unsupported backup format.')
        for name in names:
            if name not in ('only-us.sqlite3','manifest.json') and not re.fullmatch(r'photos/[0-9a-f]{32}\.webp',name):
                raise SystemExit('Unexpected archive entry. Nothing was restored.')
        destination.mkdir(mode=0o700,parents=True,exist_ok=True)
        (destination/'photos').mkdir(mode=0o700,exist_ok=True)
        for name in names:
            if name!='manifest.json':
                (destination/name).write_bytes(archive.read(name))
    with sqlite3.connect(destination/'only-us.sqlite3') as con:
        if con.execute('PRAGMA quick_check').fetchone()[0]!='ok':
            raise SystemExit('Database validation failed; do not start this restored copy.')
        if {r[0] for r in con.execute('SELECT id FROM users')}!={'Ahmed','Mahra'}:
            raise SystemExit('Unexpected accounts in this backup.')
        con.execute('DELETE FROM sessions')
        for (name,) in con.execute('SELECT filename FROM photos'):
            if not (destination/'photos'/name).is_file():
                raise SystemExit('Missing photo in restored backup.')
    print(f'Restored into {destination.resolve()}. Set DATA_DIR to this directory, then restart the server. Everyone must sign in again.')


def reset_password(user: str) -> None:
    password=getpass.getpass(f'New temporary password for {user} (at least 12 characters): ')
    confirm=getpass.getpass('Repeat password: ')
    if password!=confirm or not 12<=len(password)<=256:
        raise SystemExit('Passwords must match and contain 12-256 characters.')
    with server.db(True) as con:
        row=con.execute('SELECT id FROM users WHERE id=?',(user,)).fetchone()
        if not row:
            raise SystemExit('Account not initialized. Check DATA_DIR.')
        con.execute('UPDATE users SET password_hash=?,must_change=1 WHERE id=?',(server.hash_password(password),user))
        con.execute('DELETE FROM sessions WHERE user_id=?',(user,))
        con.execute('DELETE FROM attempts WHERE bucket=?',('login-user:'+user,))
        server.change(con)
    print('Password reset. All existing sessions for this account were revoked. A new password will be required at sign-in.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    b=commands.add_parser('backup');b.add_argument('destination',type=Path);b.add_argument('--server-stopped',action='store_true',required=True,help='Confirm the server is stopped for a consistent database and photo snapshot.')
    r=commands.add_parser('restore');r.add_argument('source',type=Path);r.add_argument('--target',type=Path,required=True);r.add_argument('--server-stopped',action='store_true',required=True)
    p=commands.add_parser('reset-password');p.add_argument('user',choices=['Ahmed','Mahra'])
    args=parser.parse_args()
    if args.command=='backup':backup(args.destination)
    elif args.command=='restore':restore(args.source,args.target)
    else:reset_password(args.user)
