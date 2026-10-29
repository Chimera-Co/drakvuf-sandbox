# Services and drivers report (read-only)
$out = Join-Path $env:TEMP "service-report.csv"
Get-CimInstance Win32_Service | Select-Object Name, State, StartMode, StartName, PathName |
    Export-Csv -NoTypeInformation -Path $out
Get-CimInstance Win32_SystemDriver | Where-Object State -eq "Running" |
    Select-Object Name, DisplayName, PathName | Format-Table -AutoSize
Write-Output "Wrote $out"
