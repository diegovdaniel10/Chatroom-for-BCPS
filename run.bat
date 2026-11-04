@echo off
setlocal
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Python 3.10 or newer is required. Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
  pause & exit /b 1
)
if not exist .env copy .env.example .env >nul
echo Starting BCPS chatroom... open http://127.0.0.1:3000 in your browser.
echo The owner claim code is printed below the first time the server starts with an empty database.
python backend\server.py
pause
