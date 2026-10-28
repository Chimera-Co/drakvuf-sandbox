# A0-scan only (goal G1.1): A0 with Microsoft Defender left as it is, plus an exclusion for the four checker
# folders, so Defender cannot delete al-khaser, Pafish or VMAware before they run (it deleted al-khaser on A0).
# The Stage 1 arm A0 is not changed. Prints Defender's state and exclusions before and after.
$folders = 'C:\Users\Public\alkhaser', 'C:\Users\Public\perdedor', 'C:\Users\Public\pafish', 'C:\Users\Public\vmaware'

function Show-Defender($when) {
    $s = Get-MpComputerStatus
    "defender_$when antivirus=$($s.AntivirusEnabled) realtime=$($s.RealTimeProtectionEnabled) " +
        "behavior=$($s.BehaviorMonitorEnabled) ioav=$($s.IoavProtectionEnabled) onaccess=$($s.OnAccessProtectionEnabled) " +
        "tamper=$($s.IsTamperProtected) engine=$($s.AMEngineVersion) signatures=$($s.AntivirusSignatureVersion)"
    "exclusions_$when=" + ((Get-MpPreference).ExclusionPath -join ';')
}

Show-Defender 'before'
Add-MpPreference -ExclusionPath $folders
Start-Sleep -Seconds 3
Show-Defender 'after'
$current = (Get-MpPreference).ExclusionPath
$missing = $folders | Where-Object { $current -notcontains $_ }
if ($missing) { "missing exclusions: $($missing -join ';')"; exit 1 }
