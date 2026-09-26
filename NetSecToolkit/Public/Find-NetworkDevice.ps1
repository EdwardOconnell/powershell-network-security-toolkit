function Find-NetworkDevice {
    <#
    .SYNOPSIS
        Lists devices on the same subnet as a network adapter (the active one by default).
    .DESCRIPTION
        Active mode runs a parallel ping sweep, then reads the ARP/neighbor table, which also
        catches devices that ignore ping. -Passive reads the neighbor table only and sends no probes.
        Only scan networks you own or are authorized to scan.
    .PARAMETER InterfaceAlias
        Adapter to scan. Default: the adapter carrying your internet traffic.
    .PARAMETER Passive
        Don't send any traffic; only report devices this PC has already seen.
    .PARAMETER ExportPath
        Save the device list to this CSV file.
    .PARAMETER PassThru
        Also return the devices as objects.
    .EXAMPLE
        Find-NetworkDevice
    .EXAMPLE
        Find-NetworkDevice -Passive -ExportPath C:\scan.csv
    #>
    [CmdletBinding()]
    param(
        [string]$InterfaceAlias,
        [switch]$Passive,
        [ValidateRange(1, 256)][int]$ThrottleLimit = 64,
        [ValidateRange(100, 5000)][int]$TimeoutMs = 500,
        [int]$MaxHosts = 1024,
        [string]$ExportPath,
        [switch]$PassThru
    )

    Assert-Windows
    if (-not $InterfaceAlias) {
        $InterfaceAlias = Get-ActiveInterfaceAlias
        if (-not $InterfaceAlias) { throw 'No connected adapter with an internet route found. Use -InterfaceAlias.' }
    }

    $ipInfo = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '169.254*' } | Select-Object -First 1
    if (-not $ipInfo) { throw "No usable IPv4 address on '$InterfaceAlias'. Check Get-NetAdapter for the right name." }

    $myIP  = $ipInfo.IPAddress
    $gw    = (Get-NetRoute -InterfaceAlias $InterfaceAlias -DestinationPrefix '0.0.0.0/0' `
                -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
    $myMac = (Get-NetAdapter -Name $InterfaceAlias).MacAddress
    $range = Get-SubnetRange -IPAddress $myIP -PrefixLength $ipInfo.PrefixLength -MaxHosts $MaxHosts
    if ($range.Narrowed) {
        Write-Warning "Subnet is larger than $MaxHosts addresses. Limiting to $($range.Cidr) (use -MaxHosts to change)."
    }

    Write-Host "`nInterface : $InterfaceAlias" -ForegroundColor Cyan
    Write-Host "This PC   : $myIP ($myMac)"
    Write-Host "Gateway   : $gw"
    Write-Host "Range     : $($range.Cidr) ($(ConvertTo-IPAddressString $range.First) - $(ConvertTo-IPAddressString $range.Last))"

    # --- Active ping sweep ---
    $pingReplies = @()
    if (-not $Passive) {
        $targets = for ($i = [uint64]$range.First; $i -le $range.Last; $i++) {
            $t = ConvertTo-IPAddressString ([uint32]$i)
            if ($t -ne $myIP) { $t }
        }
        Write-Host "`nPinging $(@($targets).Count) addresses..." -ForegroundColor Cyan
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $pingReplies = @($targets | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
            $p = [System.Net.NetworkInformation.Ping]::new()
            try { if ($p.Send($_, $using:TimeoutMs).Status -eq 'Success') { $_ } } catch { } finally { $p.Dispose() }
        })
        Write-Host "Sweep done in $([math]::Round($sw.Elapsed.TotalSeconds, 1))s. $($pingReplies.Count) replied to ping."
    }

    # --- Neighbor (ARP) table: catches devices that ignore ping ---
    $neighbors = @{}
    Get-NetNeighbor -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.State -notin 'Unreachable', 'Incomplete', 'Permanent' -and
            $_.LinkLayerAddress -notin '00-00-00-00-00-00', 'FF-FF-FF-FF-FF-FF', ''
        } |
        ForEach-Object {
            $n = ConvertTo-UInt32 $_.IPAddress
            if ($n -ge $range.First -and $n -le $range.Last) { $neighbors[$_.IPAddress] = $_ }
        }

    $allIPs = @($pingReplies) + @($neighbors.Keys) + @($myIP) | Sort-Object -Unique

    # --- Reverse name lookups in parallel ---
    Write-Host "Resolving names for $($allIPs.Count) devices..." -ForegroundColor Cyan
    $names = @{}
    $allIPs | ForEach-Object -ThrottleLimit 32 -Parallel {
        $n = try {
            (Resolve-DnsName -Name $_ -QuickTimeout -ErrorAction Stop |
                Where-Object NameHost | Select-Object -First 1).NameHost
        } catch { $null }
        [pscustomobject]@{ IP = $_; Name = $n }
    } | ForEach-Object { $names[$_.IP] = $_.Name }

    $devices = foreach ($ip in $allIPs) {
        $nb  = $neighbors[$ip]
        $mac = if ($ip -eq $myIP) { $myMac } else { $nb.LinkLayerAddress }
        [pscustomobject]@{
            IP        = $ip
            Role      = if ($ip -eq $myIP) { 'This PC' } elseif ($ip -eq $gw) { 'Gateway' } else { '' }
            Hostname  = $names[$ip]
            MAC       = $mac
            RandomMAC = if ($mac) { Test-RandomizedMac $mac } else { $null }
            Ping      = if ($Passive) { 'n/a' } else { $ip -in $pingReplies -or $ip -eq $myIP }
            ARPState  = if ($ip -eq $myIP) { 'Self' } else { "$($nb.State)" }
        }
    }
    $devices = @($devices | Sort-Object { ConvertTo-UInt32 $_.IP })

    Write-Section "Devices found: $($devices.Count)"
    $devices | Show-Table

    if ($ExportPath) {
        $devices | Export-Csv -Path $ExportPath -NoTypeInformation
        Write-Host "Exported to $ExportPath"
    }
    if (-not @($devices | Where-Object { $_.Role -eq '' }).Count) {
        Write-Host 'Only this PC and the gateway are visible. The network likely uses client isolation.' -ForegroundColor Yellow
    }

    if ($PassThru) { $devices }
}
