@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Python environment missing. See README.md.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" run_demo.py
if errorlevel 1 pause
