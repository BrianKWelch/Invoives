@echo off
title Invoice App Setup & Launch
color 0A
echo ========================================
echo   Invoice App - Setup and Launch
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed!
    echo.
    echo Please install Python from: https://www.python.org/downloads/
    echo IMPORTANT: Check "Add Python to PATH" during installation
    echo.
    pause
    exit /b 1
)

echo [OK] Python is installed
echo.

REM Change to script directory
cd /d "%~dp0"

REM Check if requirements are installed
echo Checking dependencies...
pip show streamlit >nul 2>&1
if errorlevel 1 (
    echo Installing required packages (this may take a minute)...
    pip install -r requirements.txt --quiet
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies
        echo Please run: pip install -r requirements.txt
        pause
        exit /b 1
    )
    echo [OK] Dependencies installed
) else (
    echo [OK] Dependencies already installed
)

echo.
echo ========================================
echo   Starting Invoice App...
echo ========================================
echo The app will open in your browser automatically.
echo Close this window to stop the app.
echo.

streamlit run invoice_app.py

pause
