# Export recent System and Application events for support (does not clear any log)
$dir = Join-Path $env:TEMP "eventlogs"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
foreach ($log in "System", "Application") {
    wevtutil epl $log (Join-Path $dir "$log.evtx") "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]"
}
Get-WinEvent -LogName System -MaxEvents 50 | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName |
    Export-Csv -NoTypeInformation -Path (Join-Path $dir "system-latest.csv")
Write-Output "Exported to $dir"
