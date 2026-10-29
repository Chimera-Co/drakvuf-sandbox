# Certificate inventory of the machine and user stores, with expiry (read-only)
$out = Join-Path $env:TEMP "cert-inventory.csv"
Get-ChildItem Cert:\LocalMachine\My, Cert:\LocalMachine\Root, Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
    Select-Object PSParentPath, Subject, Issuer, NotAfter, Thumbprint |
    Export-Csv -NoTypeInformation -Path $out
Get-ChildItem Cert:\LocalMachine\My | Where-Object NotAfter -lt (Get-Date).AddDays(30) |
    Select-Object Subject, NotAfter | Format-Table
Write-Output "Wrote $out"
