function Get-NetAdapterHealth {
    <#
    .SYNOPSIS
        Checks every network adapter for link state, IP, gateway reachability, driver health,
        packet errors, and internet/DNS access.
    .DESCRIPTION
        Read-only. Adapters that aren't physically present are listed but not queried.
        Devices disabled on purpose in Device Manager are marked as disabled, not as errors.
    .PARAMETER PassThru
        Also return the results as objects.
    .EXAMPLE
        Get-NetAdapterHealth
    .EXAMPLE
        $health = Get-NetAdapterHealth -PassThru
        $health.Adapters | Where-Object APIPA
    #>
    [CmdletBinding()]
    param([switch]$PassThru)

    Assert-Administrator

    Write-Section 'Adapter status'
    $adapters = @(foreach ($a in Get-NetAdapter) {
        $cfg = if ($a.Status -ne 'Not Present') {
            Get-NetIPConfiguration -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue
        }
        $ip = $cfg.IPv4Address.IPAddress | Select-Object -First 1
        $gw = $cfg.IPv4DefaultGateway.NextHop | Select-Object -First 1
        $gwPing = if ($gw) {
            Test-Connection -TargetName $gw -Count 1 -TimeoutSeconds 2 -Quiet -ErrorAction SilentlyContinue
        }
        [pscustomobject]@{
            Name    = $a.Name
            Status  = $a.Status
            Speed   = $a.LinkSpeed
            IPv4    = $ip
            APIPA   = [bool]($ip -like '169.254*')
            Gateway = $gw
            GW_Ping = $gwPing
        }
    })
    $adapters | Show-Table

    Write-Section 'Driver / device health'
    $drivers = @(Get-PnpDevice -Class Net -PresentOnly -ErrorAction SilentlyContinue |
        Select-Object FriendlyName, Status, Problem,
            @{ n = 'Note'; e = { if (Test-DeviceDisabled $_) { 'Disabled' } } })
    $drivers | Show-Table

    Write-Section 'Packet errors'
    $stats = @(Get-NetAdapterStatistics -ErrorAction SilentlyContinue |
        Select-Object Name, ReceivedPacketErrors, OutboundPacketErrors,
                      ReceivedDiscardedPackets, OutboundDiscardedPackets)
    $stats | Show-Table

    Write-Section 'Internet / DNS'
    $internet = [pscustomobject]@{
        'Ping 8.8.8.8' = Test-Connection -TargetName 8.8.8.8 -Count 1 -TimeoutSeconds 2 -Quiet -ErrorAction SilentlyContinue
        'DNS resolve'  = $(try { [bool](Resolve-DnsName google.com -Type A -QuickTimeout -ErrorAction Stop) } catch { $false })
        'HTTPS 443'    = Test-NetConnection google.com -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
    }
    $internet | Show-Table

    if ($PassThru) {
        [pscustomobject]@{ Adapters = $adapters; Drivers = $drivers; PacketErrors = $stats; Internet = $internet }
    }
}
