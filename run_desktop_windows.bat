@echo off
cd /d "%~dp0"
python desktop_app.py
if errorlevel 1 (
  echo.
  echo Python could not start the application. Install Python 3.10+ from python.org and enable "Add Python to PATH".
  pause
)
