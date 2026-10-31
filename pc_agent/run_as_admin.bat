@echo off
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :run
) else (
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~dp0run_as_admin.bat\"\"' -Verb RunAs"
    exit /b
)

:run
cd /d "%~dp0"
title WinKey Admin Serveri
python server.py
pause
