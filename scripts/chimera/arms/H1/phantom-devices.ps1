# Removes devices Windows still remembers from boots on the default Xen/QEMU hardware
# (Xen platform PCI device, QEMU disk and audio) but that are no longer present.
# Their Enum\PCI, Enum\IDE and Enum\SCSI registry entries stay behind and are what
# al-khaser's "Enum\PCI\VEN_5853" and "Enum\IDE and Enum\SCSI" checks find on H1.
# Run it in a modify-vm0 session with -WhatIf first to see the list.
param([switch]$WhatIf)

# Instance ID substrings of the default Xen/QEMU hardware: Xen platform device
# (vendor 5853), QEMU/virtio vendor 1AF4 (HDA codec), QEMU disk and DVD models.
$patterns = 'VEN_5853', 'VEN_1AF4', 'QEMU', 'XEN'
function Get-VmPhantoms {
    Get-PnpDevice | Where-Object {
        $id = $_.InstanceId
        -not $_.Present -and ($patterns | Where-Object { $id -like "*$_*" })
    }
}

$phantoms = @(Get-VmPhantoms)
foreach ($device in $phantoms) {
    if ($WhatIf) {
        Write-Output "would remove: $($device.InstanceId)"
        continue
    }
    # pnputil /remove-device needs Windows 10 2004 or later.
    $output = pnputil /remove-device "$($device.InstanceId)" 2>&1
    Write-Output "remove $($device.InstanceId): exit $LASTEXITCODE $($output -join ' ')"
}

$left = @(Get-VmPhantoms)
Write-Output "phantom_vm_devices_before=$($phantoms.Count) after=$($left.Count)"
if (-not $WhatIf -and $left.Count) { exit 1 }
