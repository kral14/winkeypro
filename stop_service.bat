@echo off
echo WinKey Xidmeti dayandirilir...
powershell -Command "Start-Process cmd -ArgumentList '/c schtasks /delete /tn WinKeyService /f & taskkill /F /FI \"COMMANDLINE eq *server.py*\" & taskkill /F /PID 56052' -Verb RunAs"
echo Dayandirildi!
pause
