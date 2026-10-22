@echo off
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  python setup_and_start.py
) else (
  py -3 setup_and_start.py
)
if errorlevel 1 echo Setup failed. Python 3.12+ and internet are required. See START-HERE.txt.
pause
