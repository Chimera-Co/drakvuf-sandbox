# Local users and group membership report (read-only)
$out = Join-Path $env:TEMP "user-audit.csv"
$rows = foreach ($g in Get-LocalGroup) {
    foreach ($m in (Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue)) {
        [pscustomobject]@{Group = $g.Name; Member = $m.Name; Type = $m.ObjectClass; Source = $m.PrincipalSource}
    }
}
$rows | Export-Csv -NoTypeInformation -Path $out
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired | Format-Table -AutoSize
Write-Output "Wrote $out"
