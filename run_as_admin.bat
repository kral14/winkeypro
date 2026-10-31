@echo off
:: Windows Administrator huququnu teleb edir
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :run
) else (
    echo Administrator huquqlari teleb olunur...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~dp0run_as_admin.bat\"\"' -Verb RunAs"
    exit /b
)

:run
cd /d "%~dp0pc_agent"
title WinKey Admin Serveri
echo ===================================================
echo     WINKEY // Administrator Rejiminde Server
echo ===================================================
python server.py
pause
