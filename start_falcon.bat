@echo off
title PROJECT FALCON - Starting Backend...
color 0B

echo.
echo  =====================================================
echo    PROJECT FALCON - AI Threat Detection System
echo  =====================================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found. Please install Python 3.8+
    echo  Download: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo  [1/3] Python found...

:: Install dependencies silently
echo  [2/3] Installing dependencies...
pip install flask flask-cors psutil --quiet --disable-pip-version-check

echo  [3/3] Starting FALCON backend...
echo.
echo  =====================================================
echo    Backend running at: http://localhost:5000
echo    Open index.html in your browser
echo    Press Ctrl+C to stop
echo  =====================================================
echo.

python server.py

pause
