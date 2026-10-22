@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo TRACE: Python environment not found. See README.md for setup.
  pause
  exit /b 1
)
echo TRACE: opening UI and API at http://127.0.0.1:5173
".venv\Scripts\python.exe" run_release.py
if errorlevel 1 pause
