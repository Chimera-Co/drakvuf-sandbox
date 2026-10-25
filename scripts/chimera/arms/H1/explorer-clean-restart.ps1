# Restarts explorer.exe so that it is winlogon's child again, before a snapshot is committed.
#
# When OneDrive updates itself it restarts explorer as its own child, and explorer inherits
# OneDrive's SetDllDirectory. drakshell runs inside explorer, so every process it starts
# (samples included) then loads msvcp140/vcruntime140 from OneDrive's folder instead of
# System32, which al-khaser reports as injected libraries (found on H2, 2026-10-19).
# Starting explorer from a scheduled task fixes that but puts it in the Task Scheduler's
# job object (al-khaser: process_in_job), and that job allows no breakaway.
#
# What worked on H2: force-stop explorer from a detached process, then activate explorer's
# COM factory class. winlogon restarted the shell (parent winlogon.exe, no job, no DLL
# directory); the /factory explorer the activation starts exits by itself or is stopped here.
# drakshell dies with the old explorer; the next provision_guest.py run injects a new one.
# Check the result with explorer-state.ps1.
$cmd = 'Start-Sleep 3; Stop-Process -Name explorer -Force; Start-Sleep 3; ' +
       'try { $null = [Activator]::CreateInstance([Type]::GetTypeFromCLSID(''75DFF2B7-6936-4C06-A8BB-676A7B00B24B'')) } catch { }; ' +
       'Start-Sleep 20; Get-CimInstance Win32_Process -Filter "Name=''explorer.exe''" | ' +
       'Where-Object CommandLine -like ''*/factory*'' | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }'
Start-Process -WindowStyle Hidden powershell.exe -ArgumentList '-NoProfile', '-Command', $cmd
"explorer restart started; run explorer-state.ps1 in about 30 s"
