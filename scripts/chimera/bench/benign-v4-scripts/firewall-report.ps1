# Windows Firewall profiles and enabled inbound rules (read-only)
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table
$out = Join-Path $env:TEMP "firewall-rules.csv"
Get-NetFirewallRule -Enabled True -Direction Inbound |
    Select-Object DisplayName, Profile, Action, Program |
    Export-Csv -NoTypeInformation -Path $out
Write-Output "Wrote $out"
