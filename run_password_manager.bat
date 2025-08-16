@echo off
echo Starting Password Manager...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed or not in PATH
    echo Please install Python from https://python.org
    pause
    exit /b 1
)

REM Install required packages if not already installed
echo Checking and installing required packages...
pip install cryptography pyotp qrcode[pil] >nul 2>&1

REM Run the password manager
echo.
python password-manager.py

echo.
echo Password Manager has closed.
pause