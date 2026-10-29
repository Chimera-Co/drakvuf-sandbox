@echo off
rem Back up the current user's Software hive before a configuration change
set OUT=%TEMP%\registry-backup
if not exist "%OUT%" mkdir "%OUT%"
reg export "HKCU\Software" "%OUT%\hkcu-software.reg" /y
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
echo Backup written to %OUT%
