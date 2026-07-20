@echo off
setlocal
cd /d "%~dp0"
python vpncheck.py
if errorlevel 1 pause
endlocal
