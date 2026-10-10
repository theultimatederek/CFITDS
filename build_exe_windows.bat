@echo off
cd /d "%~dp0"
python -m pip install pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --windowed --name CFITDS desktop_app.py
echo.
echo Build complete. Open the dist folder and run CFITDS.exe
pause
