@echo off
:: Windows Administrator huququnu teleb edir
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Administrator huququ teleb olunur...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~dp0install_winkey_service.bat\"\"' -Verb RunAs"
    exit /b
)

cd /d "%~dp0pc_agent"
echo =============================================================
echo   WINKEY // Windows SYSTEM Xidmeti Kimi Qurasdirma
echo =============================================================
echo [1] Kohler xidmet ve prosesler dayandirilir...
schtasks /delete /tn "WinKeyService" /f >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8888 ^| findstr LISTENING') do taskkill /F /PID %%a >nul 2>&1

echo [2] Windows Firewall-da port 8888 acilir...
netsh advfirewall firewall delete rule name="WinKey Port 8888" >nul 2>&1
netsh advfirewall firewall add rule name="WinKey Port 8888" dir=in action=allow protocol=TCP localport=8888

echo [3] Avtomatik SYSTEM tapsirigi yaradilir...
for /f "delims=" %%i in ('where python.exe') do set "PYTHON_PATH=%%i" & goto :found_python
:found_python

echo Python yolu: %PYTHON_PATH%
schtasks /create /tn "WinKeyService" /tr "\"%PYTHON_PATH%\" \"%~dp0pc_agent\server.py\"" /sc onstart /ru "NT AUTHORITY\SYSTEM" /rl HIGHEST /f

echo [4] Xidmet ise salinir...
schtasks /run /tn "WinKeyService"

echo =============================================================
echo   TEBRIKLER! WinKey SYSTEM hesabi ile ise salindi.
echo   Artiq kompyuter kilidli olanda bele parol avtomatik yazilacaq!
echo =============================================================
pause
