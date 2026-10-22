"""Single-process, same-origin local release launcher. Never starts Vite."""
from __future__ import annotations
from contextlib import closing
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import sys
from urllib.parse import unquote,urlsplit

ROOT=Path(__file__).resolve().parent
class ReleaseError(ValueError):pass

def frontend_path(explicit=None):
    candidates=[Path(explicit)] if explicit else [ROOT/'frontend/dist',ROOT.parent/'trace-frontend/dist']
    for path in candidates:
        path=path.resolve()
        if (path/'index.html').is_file():return path
    raise ReleaseError('Сборка интерфейса отсутствует. Соберите frontend или задайте --frontend.')

def inspect_frontend(path):
    try:html=(path/'index.html').read_text(encoding='utf-8-sig')
    except (OSError,UnicodeError) as exc:raise ReleaseError('Не удалось прочитать index.html.') from exc
    references=re.findall(r'(?:src|href)=[\"\']([^\"\']+)',html)
    assets=[]
    for ref in references:
        uri=urlsplit(ref)
        if uri.scheme or uri.netloc:continue
        name=unquote(uri.path).lstrip('/')
        if not name or name.startswith('data:'):continue
        if name.startswith('src/') or name=='@vite/client':raise ReleaseError('Нужна production-сборка frontend, а не исходный index.html.')
        file=(path/name).resolve()
        if not file.is_relative_to(path) or not file.is_file():raise ReleaseError('В сборке отсутствует файл: '+name)
        assets.append(name)
    if not any(name.endswith('.js') for name in assets):raise ReleaseError('В index.html нет JavaScript-сборки.')
    return assets

def preflight(database,frontend,port,initialize=False):
    if not 1024<=port<=65535:raise ReleaseError('Порт должен быть от 1024 до 65535.')
    missing=[name for name in ('fastapi','uvicorn','sqlalchemy') if importlib.util.find_spec(name) is None]
    if missing:raise ReleaseError('Не установлены зависимости: '+', '.join(missing)+'. Используйте .venv и requirements.txt.')
    assets=inspect_frontend(frontend)
    if not database.exists():
        if not initialize:raise ReleaseError('База отсутствует. Укажите существующую --database или явно создайте новую через --init.')
        if not database.parent.is_dir():raise ReleaseError('Каталог новой базы не существует.')
        state='new_database_requested'
    else:
        if not database.is_file():raise ReleaseError('Путь базы не является файлом.')
        try:
            with closing(sqlite3.connect(database.as_uri()+'?mode=ro',uri=True)) as db:
                if db.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise ReleaseError('Проверка целостности SQLite не пройдена.')
                tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not {'projects','scans','findings'}.issubset(tables):raise ReleaseError('Файл не является базой TRACE.')
        except sqlite3.DatabaseError as exc:raise ReleaseError('Не удалось прочитать базу SQLite.') from exc
        state='existing_database_verified'
    return dict(database=str(database),databaseState=state,frontend=str(frontend),assets=assets,
        url='http://127.0.0.1:'+str(port),mode='single_process_static_release')

def main(argv=None):
    parser=argparse.ArgumentParser(description='TRACE: интерфейс и API одним процессом без Vite.')
    parser.add_argument('--port',type=int,default=5173)
    parser.add_argument('--database',type=Path,default=ROOT/'trace_api/trace-platform.db')
    parser.add_argument('--frontend',type=Path)
    parser.add_argument('--init',action='store_true',help='Разрешить создание новой базы, если её нет.')
    parser.add_argument('--check',action='store_true',help='Только проверить файлы и базу, ничего не запускать.')
    args=parser.parse_args(argv)
    try:
        database=args.database.resolve();frontend=frontend_path(args.frontend)
        value=preflight(database,frontend,args.port,args.init)
        if args.check:
            print(json.dumps(value,ensure_ascii=False));return 0
        with socket.socket() as probe:
            if probe.connect_ex(('127.0.0.1',args.port))==0:raise ReleaseError('Порт '+str(args.port)+' уже занят. Остановите прежний запуск или выберите --port.')
        os.environ['TRACE_DATABASE_URL']='sqlite:///'+database.as_posix()
        os.environ['TRACE_FRONTEND_DIST']=str(frontend)
        print('TRACE: '+value['url']+' | Ctrl+C для остановки',flush=True)
        import uvicorn
        uvicorn.run('trace_api.main:app',host='127.0.0.1',port=args.port,reload=False)
        return 0
    except (ReleaseError,OSError) as exc:
        print('TRACE: '+str(exc),file=sys.stderr);return 1

if __name__=='__main__':raise SystemExit(main())
