"""Launch the updated local platform paired with the frontend on port 5173."""
import os
from pathlib import Path
import uvicorn

if __name__ == '__main__':
    root = Path(__file__).resolve().parent
    database = root / 'trace_api' / 'trace-platform.db'
    if not database.exists():
        raise SystemExit('Platform database is missing; migrate a verified copy before starting this launcher.')
    os.environ['TRACE_DATABASE_URL'] = 'sqlite:///' + database.as_posix()
    uvicorn.run('trace_api.main:app', host='127.0.0.1', port=8005, reload=False)
