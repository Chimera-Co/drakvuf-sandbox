# Prints what the guest reports about its hardware and protection, one key=value per line,
# for check_identity.py to compare with the arm's cfg.template.
$bios = Get-CimInstance Win32_BIOS
$cs = Get-CimInstance Win32_ComputerSystem
$board = Get-CimInstance Win32_BaseBoard
$nic = Get-CimInstance Win32_NetworkAdapter -Filter 'PhysicalAdapter=True' | Select-Object -First 1
$mp = Get-MpComputerStatus
$info = [ordered]@{
    bios_vendor            = $bios.Manufacturer
    bios_version           = $bios.SMBIOSBIOSVersion
    system_manufacturer    = $cs.Manufacturer
    system_product_name    = $cs.Model
    system_serial_number   = $bios.SerialNumber
    baseboard_manufacturer = $board.Manufacturer
    baseboard_product_name = $board.Product
    baseboard_serial_number = $board.SerialNumber
    enclosure_manufacturer = (Get-CimInstance Win32_SystemEnclosure).Manufacturer
    disk_model             = (Get-CimInstance Win32_DiskDrive | Select-Object -First 1).Model
    mac                    = $nic.MACAddress
    nic_name               = $nic.Name
    logical_processors     = $cs.NumberOfLogicalProcessors
    memory_mb              = [int]($cs.TotalPhysicalMemory / 1MB)
    xen_pci_devices        = @(Get-PnpDevice -PresentOnly | Where-Object InstanceId -like '*VEN_5853*').Count
    # Windows builds Win32_BIOS.Version from the ACPI OEM ID and revision ("Xen - 0" from hvmloader).
    acpi_oem_version       = $bios.Version
    # Remembered but absent Xen/QEMU devices leave Enum\PCI, Enum\IDE and Enum\SCSI entries.
    phantom_vm_devices     = @(Get-PnpDevice | Where-Object { $id = $_.InstanceId; -not $_.Present -and
                                 ('VEN_5853', 'VEN_1AF4', 'QEMU', 'XEN' | Where-Object { $id -like "*$_*" }) }).Count
    defender_realtime      = $mp.RealTimeProtectionEnabled
    defender_tamper        = $mp.IsTamperProtected
    vcruntime140           = Test-Path "$env:SystemRoot\System32\vcruntime140.dll"
}
$info.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
