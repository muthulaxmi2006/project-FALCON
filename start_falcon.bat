@echo off
title PROJECT FALCON - Launching...
color 0B
cls

echo.
echo  =====================================================
echo        PROJECT FALCON  v4.2.1
echo        AI-Powered Network Intrusion Detection
echo  =====================================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found!
    echo  Please install Python from https://www.python.org
    pause
    exit /b 1
)

echo  [1/3] Python detected...

:: Install dependencies
echo  [2/3] Checking dependencies...
pip install flask flask-cors psutil --quiet --disable-pip-version-check 2>nul

echo  [3/3] Starting FALCON server...
echo.
echo  =====================================================
echo    URL      : http://localhost:5000
echo    Browser  : Opens automatically
echo    Stop     : Press Ctrl+C in this window
echo  =====================================================
echo.

:: Start server (browser opens automatically from server.py)
python server.py

echo.
echo  Server stopped.
pause
