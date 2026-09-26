function Test-NetworkSpeed {
    <#
    .SYNOPSIS
        Shows which network and router you're connected to, then runs a speed test.
    .DESCRIPTION
        Network: adapter, SSID, band, channel, signal, link rate, Wi-Fi security, router, ISP.
        Supports Wi-Fi 7 multi-link (MLO) connections.
        Speed: router ping, internet latency and jitter, download and upload over parallel
        connections to Cloudflare's speed test endpoints. Results are appended to a CSV history.
    .PARAMETER Seconds
        Target duration of each download/upload phase.
    .PARAMETER Streams
        Number of parallel connections.
    .PARAMETER NoUpload
        Skip the upload test.
    .PARAMETER LogPath
        CSV file for the result history.
    .PARAMETER PassThru
        Also return the result as an object.
    .EXAMPLE
        Test-NetworkSpeed
    .EXAMPLE
        Test-NetworkSpeed -Seconds 15
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(3, 60)][int]$Seconds = 8,
        [ValidateRange(1, 16)][int]$Streams = 4,
        [switch]$NoUpload,
        [string]$LogPath = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'SecurityChecks\SpeedTests.csv'),
        [switch]$PassThru
    )

    Assert-Windows
    $base = $script:SpeedTestBase

    # ---------------------------------------------------------- network info ----
    $upIdx = @(Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -ExpandProperty ifIndex)
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
             Where-Object { $_.ifIndex -in $upIdx } | Sort-Object RouteMetric | Select-Object -First 1
    if (-not $route) { throw 'No active internet connection found.' }

    $adapter = Get-NetAdapter -InterfaceIndex $route.ifIndex
    $gw      = $route.NextHop
    $ip      = (Get-NetIPAddress -InterfaceIndex $route.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Select-Object -First 1).IPAddress
    $dns     = (Get-DnsClientServerAddress -InterfaceIndex $route.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses -join ', '
    $gwName  = try { (Resolve-DnsName $gw -QuickTimeout -ErrorAction Stop | Select-Object -First 1).NameHost } catch { '' }
    $gwMac   = (Get-NetNeighbor -IPAddress $gw -ErrorAction SilentlyContinue | Select-Object -First 1).LinkLayerAddress

    $wifi = $null
    $isWifi = $adapter.PhysicalMediaType -match '802\.11|Wireless' -or $adapter.InterfaceDescription -match 'Wi-?Fi|Wireless'
    if ($isWifi) {
        $wifi = @(ConvertFrom-NetshWlanInterface -Text (netsh wlan show interfaces)) |
                Where-Object { $_.Name -eq $adapter.Name } | Select-Object -First 1
    }

    $meta = try { Invoke-RestMethod "$base/meta" -TimeoutSec 5 } catch { $null }
    if (-not $meta.clientIp) {
        $trace = try { Invoke-RestMethod 'https://www.cloudflare.com/cdn-cgi/trace' -TimeoutSec 5 } catch { '' }
        $t = @{}; foreach ($l in ($trace -split "`n")) { if ($l -match '^(\w+)=(.*)$') { $t[$Matches[1]] = $Matches[2].Trim() } }
        $info = try { Invoke-RestMethod 'https://ipinfo.io/json' -TimeoutSec 5 } catch { $null }
        $meta = [pscustomobject]@{ clientIp = $t['ip'] ?? $info.ip; asOrganization = $info.org; colo = $t['colo'] }
    }

    Write-Section 'Connected network'
    $net = [ordered]@{
        'Adapter'    = "$($adapter.Name) ($($adapter.InterfaceDescription))"
        'Link speed' = $adapter.LinkSpeed
    }
    $band = 'Wired'; $channel = ''
    if ($wifi) {
        $net['Network (SSID)'] = $wifi['SSID']
        $net['Access point']   = $wifi['AP BSSID'] ?? $wifi['BSSID'] ?? $wifi['MLD AP BSSID']
        $links = $wifi['_links']
        if ($links) {
            $net['Wi-Fi 7 links'] = ($links | ForEach-Object {
                "$($_.Band) ch $($_.Channel), $($_.Width) MHz, $($_.Rssi) dBm" }) -join '  |  '
            $band    = ($links.Band | Select-Object -Unique) -join ' + '
            $channel = $links.Channel -join ' + '
        } else {
            $band = $wifi['Band']; $channel = $wifi['Channel']
            $net['Band / Channel'] = "$band / channel $channel".Trim(' /')
        }
        $net['Wi-Fi standard'] = $wifi['Radio type']
        $net['Signal']         = $wifi['Signal']
        $net['Link rate']      = "$($wifi['Receive rate (Mbps)']) Mbps down / $($wifi['Transmit rate (Mbps)']) Mbps up"
        $net['Security']       = $wifi['Authentication']
    }
    $net['This PC'] = $ip
    $net['Router']  = "$gw  $gwName  $gwMac".Trim()
    $net['DNS']     = $dns
    if ($meta.clientIp) {
        if ($meta.asOrganization) {
            $net['ISP'] = if ($meta.asn) { "$($meta.asOrganization) (AS$($meta.asn))" } else { $meta.asOrganization }
        }
        $net['Public IP'] = $meta.clientIp
        if ($meta.colo) { $net['Test server'] = "Cloudflare $($meta.colo)" }
    }
    $net.GetEnumerator() | ForEach-Object { Write-Host ('  {0,-15} {1}' -f $_.Key, $_.Value) }
    if ($wifi -and $wifi['Authentication'] -notmatch 'WPA3|WPA2') {
        Write-Host "  [!] Weak or unknown Wi-Fi security: $($wifi['Authentication'])" -ForegroundColor Red
    }

    # ---------------------------------------------------------- speed test ----
    Write-Section 'Speed test'
    $gwPings = @(1..10 | ForEach-Object {
        $r = Test-Connection -TargetName $gw -Count 1 -TimeoutSeconds 1 -ErrorAction SilentlyContinue
        if ($r.Status -eq 'Success') { $r.Latency }
    })
    $gwPing = if ($gwPings.Count) { [math]::Round(($gwPings | Measure-Object -Average).Average, 1) }
    Write-Host ('  Router ping      {0}' -f $(if ($null -ne $gwPing) { "$gwPing ms  ($($gwPings.Count)/10 replies)" } else { 'no reply' }))

    $h = [System.Net.Http.HttpClient]::new(); $h.Timeout = [TimeSpan]::FromSeconds(10)
    $samples = @()
    try {
        $h.GetAsync("$base/__down?bytes=0").GetAwaiter().GetResult().Dispose()   # warm up the connection
        $samples = @(1..10 | ForEach-Object {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $h.GetAsync("$base/__down?bytes=0").GetAwaiter().GetResult().Dispose()
            $sw.Stop(); $sw.Elapsed.TotalMilliseconds
        })
    } catch { } finally { $h.Dispose() }
    $lat = Get-LatencyStat -Samples $samples
    if (-not $lat) { throw 'Internet latency could not be measured. Check your connection.' }
    Write-Host "  Internet latency $($lat.Median) ms  (jitter $($lat.Jitter) ms)"

    Write-Host '  Download         testing...' -NoNewline
    $warm = Invoke-Transfer -Direction Down -TotalBytes 20MB -Count $Streams
    $down = if ($warm) {
        Invoke-Transfer -Direction Down -TotalBytes (Get-TestSize $warm.Mbps 10MB 400MB $Seconds) -Count $Streams
    }
    Write-Host ("`r  Download         {0}" -f $(if ($down) { "$($down.Mbps) Mbps  ($($down.MB) MB in $($down.Seconds)s)" } else { 'failed' }))

    $up = $null
    if (-not $NoUpload) {
        Write-Host '  Upload           testing...' -NoNewline
        $warmUp = Invoke-Transfer -Direction Up -TotalBytes 8MB -Count $Streams
        $up = if ($warmUp) {
            Invoke-Transfer -Direction Up -TotalBytes (Get-TestSize $warmUp.Mbps 4MB 100MB $Seconds) -Count $Streams
        }
        Write-Host ("`r  Upload           {0}" -f $(if ($up) { "$($up.Mbps) Mbps  ($($up.MB) MB in $($up.Seconds)s)" } else { 'failed' }))
    }

    # ---------------------------------------------------------- save + compare ----
    $row = [pscustomobject]@{
        Date         = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        Computer     = $env:COMPUTERNAME
        Network      = if ($wifi) { $wifi['SSID'] } else { "$($adapter.Name) (wired)" }
        Router       = if ($gwName) { $gwName } else { $gw }
        Band         = $band
        Channel      = $channel
        Signal       = if ($wifi) { $wifi['Signal'] } else { '' }
        LinkRateMbps = if ($wifi) { $wifi['Receive rate (Mbps)'] } else { $adapter.LinkSpeed }
        RouterPingMs = $gwPing
        LatencyMs    = $lat.Median
        JitterMs     = $lat.Jitter
        DownMbps     = $down.Mbps
        UpMbps       = $up.Mbps
    }
    New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null
    $row | Export-Csv -Path $LogPath -Append -NoTypeInformation

    Write-Section 'Recent results'
    Import-Csv $LogPath | Select-Object -Last 8 |
        Select-Object Date, Network, Router, Band, Signal, RouterPingMs, LatencyMs, DownMbps, UpMbps | Show-Table
    Write-Host "Full history: $LogPath" -ForegroundColor Green

    if ($PassThru) { $row }
}
