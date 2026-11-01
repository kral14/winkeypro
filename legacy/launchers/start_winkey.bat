@echo off
title WinKey Mobil Kilid Serveri
cd /d "%~dp0..\..\pc_agent"
echo ===================================================
echo     WINKEY // Windows Mobil Kilid Sistemi
echo ===================================================
echo Server ise salinir...
python server.py
pause
