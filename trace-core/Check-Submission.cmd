@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Python environment missing. See SUBMISSION.md.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" tools\check_submission.py
set "trace_check_result=%errorlevel%"
pause
exit /b %trace_check_result%
