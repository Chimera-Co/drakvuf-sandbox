# Turns Microsoft Defender off in the analysis guest so samples actually execute
# (with it on, uploads are deleted with ERROR_VIRUS_INFECTED before DRAKVUF sees them).
# Tamper Protection blocks all of this and can only be turned off by hand in the
# Windows Security app, so the script refuses to run while it is still on.
$status = Get-MpComputerStatus
if ($status.IsTamperProtected) {
    Write-Output 'Tamper Protection is still on: turn it off in Windows Security first.'
    exit 2
}

Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true `
    -DisableIOAVProtection $true -DisableScriptScanning $true -DisableBlockAtFirstSeen $true `
    -MAPSReporting Disabled -SubmitSamplesConsent NeverSend

# Policy keys so the settings survive Defender platform updates and restarts.
$policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
$values = @{
    $policy                                 = @{ DisableAntiSpyware = 1; DisableRoutinelyTakingAction = 1 }
    "$policy\Real-Time Protection"          = @{ DisableRealtimeMonitoring = 1; DisableBehaviorMonitoring = 1;
                                                 DisableOnAccessProtection = 1; DisableScanOnRealtimeEnable = 1;
                                                 DisableIOAVProtection = 1 }
    "$policy\Spynet"                        = @{ SpynetReporting = 0; SubmitSamplesConsent = 2 }
    # Defender SmartScreen would otherwise prompt before unknown executables run.
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' = @{ EnableSmartScreen = 0 }
}
foreach ($key in $values.Keys) {
    # Not New-Item -Force: on an existing key that means "replace it", which Defender refuses
    # for its own policy key, so none of the values below were written (found 2026-10-19).
    if (-not (Test-Path $key)) { New-Item -Path $key | Out-Null }
    foreach ($name in $values[$key].Keys) {
        New-ItemProperty -Path $key -Name $name -Value $values[$key][$name] -PropertyType DWord -Force | Out-Null
    }
}

Start-Sleep -Seconds 5
$status = Get-MpComputerStatus
Write-Output ("defender: realtime={0} behavior={1} ioav={2} onaccess={3} tamper={4}" -f `
    $status.RealTimeProtectionEnabled, $status.BehaviorMonitorEnabled, $status.IoavProtectionEnabled, `
    $status.OnAccessProtectionEnabled, $status.IsTamperProtected)
if ($status.RealTimeProtectionEnabled -or $status.BehaviorMonitorEnabled -or $status.IoavProtectionEnabled) { exit 1 }
exit 0
