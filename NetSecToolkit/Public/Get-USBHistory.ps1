function Get-USBHistory {
    <#
    .SYNOPSIS
        Lists every USB storage device that has been connected to this PC.
    .DESCRIPTION
        Reads HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR, where Windows records each
        USB disk and card reader with its serial number, and reports whether USB
        storage is blocked (USBSTOR Start = 4). Invoke-DailySecurityCheck uses this to
        flag new devices since the last check. Changes nothing.
    .PARAMETER PassThru
        Also return the devices and findings as an object.
    .EXAMPLE
        Get-USBHistory
    #>
    [CmdletBinding()]
    param([switch]$PassThru)

    Assert-Windows
    $findings = [System.Collections.Generic.List[object]]::new()
    Write-Section 'USB storage devices ever connected'

    $root = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
    $devices = @(foreach ($model in @(Get-RegSubKeyName -Path $root)) {
        foreach ($inst in @(Get-RegSubKeyName -Path "$root\$model")) {
            $name = Get-RegValue -Path "$root\$model\$inst" -Name 'FriendlyName'
            ConvertTo-UsbStorageRecord -ModelKey $model -InstanceKey $inst -FriendlyName "$name"
        }
    }) | Sort-Object Device
    $devices = @($devices)
    $devices | Select-Object Device, Kind, Serial, NoSerial | Show-Table

    Add-Finding $findings USB Info "$($devices.Count) USB storage device(s) have been connected to this PC."

    $start = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' -Name 'Start'
    if ($null -ne $start -and [int]$start -eq 4) {
        Add-Finding $findings USB OK 'USB storage is blocked (USBSTOR Start = 4).'
    } else {
        Add-Finding $findings USB Info 'USB storage is allowed. Windows does not run programs from USB drives by itself; scan drives you do not know before opening files on them.'
    }

    Save-RunFinding -Name 'Get-USBHistory' -Finding $findings
    if ($PassThru) {
        [pscustomobject]@{ Devices = $devices; Findings = $findings.ToArray() }
    }
}
