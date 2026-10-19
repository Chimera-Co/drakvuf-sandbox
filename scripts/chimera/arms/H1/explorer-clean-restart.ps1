# Restarts explorer.exe from the Task Scheduler so it starts with a clean environment.
#
# When OneDrive updates itself it restarts explorer as its own child, and explorer inherits
# OneDrive's SetDllDirectory. drakshell runs inside explorer, so every process it starts
# (samples included) then loads msvcp140/vcruntime140 from OneDrive's folder instead of
# System32, which al-khaser reports as injected libraries (found on H2, 2026-10-19).
# winlogon does not restart a force-killed explorer, so a one-off scheduled task does.
# drakshell dies with the old explorer; the next provision_guest.py run injects a new one.
$task = 'ChimeraCleanExplorer'
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\explorer.exe"
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive
Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Force | Out-Null

# Detached, because this script's own parent (drakshell in explorer) is about to go away.
$steps = "timeout /t 3 /nobreak >nul & taskkill /f /im explorer.exe & timeout /t 2 /nobreak >nul" +
         " & schtasks /run /tn $task & timeout /t 10 /nobreak >nul & schtasks /delete /tn $task /f"
Start-Process -WindowStyle Hidden cmd.exe -ArgumentList "/c $steps"
"explorer restart scheduled via task $task"
