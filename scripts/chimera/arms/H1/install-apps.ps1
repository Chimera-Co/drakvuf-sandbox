# Installs everyday applications machine-wide, so that the uninstall list looks like a used
# laptop's (PERDEDOR win.behavioural.installed_programs counts HKLM uninstall entries with a
# DisplayName and wants at least 20; H2 had 8 on 2026-10-20). Per-user installs land in HKCU
# and would not count, hence the machine-wide installers.
#
# The installers come from fetch-apps.sh and are uploaded into $Dir by provision_guest.py
# --upload. Each one runs only if its Authenticode signature is valid (or, for an unsigned one,
# its sha256 matches the pinned value); -CheckOnly lists the
# signers without installing anything. The installers are left in Downloads, as a user's
# would be. Updaters are switched off afterwards so that they neither run nor reach the
# network during an analysis.
param(
    [string]$Dir = (Join-Path $env:USERPROFILE 'Downloads'),
    [switch]$CheckOnly
)

# 0 = done, 3010/1641 = done with a reboot pending, 1638 = this or a newer version is installed.
$okCodes = 0, 1638, 1641, 3010
$apps = @(
    @{ File = 'VC_redist.x86.exe';                         Args = '/install /quiet /norestart' }
    @{ File = 'googlechromestandaloneenterprise64.msi';    Args = '' }
    @{ File = 'Firefox Setup *.msi';                       Args = 'INSTALL_MAINTENANCE_SERVICE=false' }
    # 7-Zip does not sign its installers: the sha256 GitHub publishes for the 26.04 release asset.
    @{ File = '7z2604-x64.msi';                            Args = '';
       Sha256 = '0b01334a418654293513449f61d6bfc99e5196ca371e3c3dc961eda57cd535c6' }
    @{ File = 'vlc-*-win64.exe';                           Args = '/L=1033 /S' }
    @{ File = 'npp.*.Installer.x64.exe';                   Args = '/S' }
    @{ File = 'LibreOffice_*_Win_x86-64.msi';              Args = 'ISCHECKFORPRODUCTUPDATES=0 REBOOTYESNO=No' }
    @{ File = 'ZoomInstallerFull.msi';                     Args = 'ZoomAutoUpdate=false' }
    @{ File = 'python-*-amd64.exe';                        Args = '/quiet InstallAllUsers=1 PrependPath=1 Include_test=0' }
    @{ File = 'Git-*-64-bit.exe';                          Args = '/VERYSILENT /NORESTART /SUPPRESSMSGBOXES /SP-' }
    @{ File = 'VSCodeSetup-x64-*.exe';                     Args = '/VERYSILENT /NORESTART /SUPPRESSMSGBOXES /MERGETASKS=!runcode' }
    @{ File = 'audacity-win-*-x86_64.msi';                 Args = '' }
    @{ File = 'putty-64bit-*-installer.msi';               Args = '' }
    @{ File = 'OpenJDK21U-jre_x64_windows_hotspot_*.msi';  Args = '' }
)

function Get-UninstallNames {
    # The same query as PERDEDOR's Test-InstalledPrograms.
    @(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } | ForEach-Object { $_.DisplayName } | Sort-Object)
}

$before = Get-UninstallNames
"uninstall entries before: $($before.Count)"
$before | ForEach-Object { "  $_" }
$failed = 0
foreach ($app in $apps) {
    $file = Get-ChildItem -Path $Dir -Filter $app.File -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $file) { "MISSING  $($app.File)"; $failed++; continue }
    $sig = Get-AuthenticodeSignature -LiteralPath $file.FullName
    if ($sig.Status -eq 'Valid') {
        $signer = $sig.SignerCertificate.GetNameInfo('SimpleName', $false)
    } elseif ($app.Sha256 -and (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -eq $app.Sha256) {
        $signer = 'unsigned, sha256 matches'
    } else {
        "UNSIGNED $($file.Name) status=$($sig.Status)"; $failed++; continue
    }
    if ($CheckOnly) { "verified $($file.Name): $signer"; continue }

    $started = Get-Date
    if ($file.Extension -eq '.msi') {
        $p = Start-Process msiexec.exe -ArgumentList "/i `"$($file.FullName)`" /qn /norestart $($app.Args)" -Wait -PassThru
    } else {
        $p = Start-Process -FilePath $file.FullName -ArgumentList $app.Args -Wait -PassThru
    }
    $secs = [int]((Get-Date) - $started).TotalSeconds
    $state = if ($p.ExitCode -in $okCodes) { 'ok' } else { $failed++; 'FAILED' }
    "{0,-6} {1} exit={2} {3}s signer={4}" -f $state, $file.Name, $p.ExitCode, $secs, $signer
}
if ($CheckOnly) { if ($failed) { exit 1 } else { exit 0 } }

# Updaters off. Google's updater starts its services right after the Chrome install.
$policies = @{
    'HKLM:\SOFTWARE\Policies\Google\Update'   = @{ UpdateDefault = 0; AutoUpdateCheckPeriodMinutes = 0 }
    'HKLM:\SOFTWARE\Policies\Mozilla\Firefox' = @{ DisableAppUpdate = 1; DisableDefaultBrowserAgent = 1 }
}
foreach ($key in $policies.Keys) {
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    foreach ($name in $policies[$key].Keys) {
        New-ItemProperty -Path $key -Name $name -Value $policies[$key][$name] -PropertyType DWord -Force | Out-Null
    }
}
Get-Service -Name 'GoogleUpdater*', 'gupdate*', 'MozillaMaintenance' -ErrorAction SilentlyContinue | ForEach-Object {
    Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
    Set-Service -Name $_.Name -StartupType Disabled
    "service disabled: $($_.Name)"
}
Get-ScheduledTask | Where-Object { $_.TaskName -like 'GoogleUpdate*' -or $_.TaskPath -like '\Mozilla\*' } | ForEach-Object {
    $null = Disable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath
    "task disabled: $($_.TaskPath)$($_.TaskName)"
}

$after = Get-UninstallNames
"uninstall entries after: $($after.Count)"
Compare-Object $before $after | Where-Object SideIndicator -eq '=>' | ForEach-Object { "  + $($_.InputObject)" }
if ($failed) { exit 1 } else { exit 0 }
