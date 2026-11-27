function Test-RouterExposure {
    <#
    .SYNOPSIS
        Checks which services a router exposes on the LAN and whether it answers UPnP,
        shows the public IP for an outside test, and can dump the router's firewall rules over SSH.
    .DESCRIPTION
        Read-only. Testing your own public IP from inside the network isn't reliable (the
        router loops it back), so use an outside scanner such as GRC ShieldsUP for the WAN side.
    .PARAMETER Router
        Router address. Default: the default gateway of the active connection.
    .PARAMETER Ssh
        Also dump iptables rules over SSH. SSH must be enabled on the router (LAN only).
    .PARAMETER NoUpnp
        Skip the UPnP (SSDP) discovery check.
    .PARAMETER NoPublicIp
        Don't look up the public IP (the lookup asks api.ipify.org).
    .PARAMETER PassThru
        Also return the port results as objects.
    .EXAMPLE
        Test-RouterExposure
    .EXAMPLE
        Test-RouterExposure -Router 192.168.1.1 -Ssh
    #>
    [CmdletBinding()]
    param(
        [string]$Router,
        [switch]$Ssh,
        [string]$SshUser = 'admin',
        [ValidateRange(1, 65535)][int]$SshPort = 22,
        [ValidateRange(100, 10000)][int]$TimeoutMs = 800,
        [switch]$NoUpnp,
        [switch]$NoPublicIp,
        [switch]$PassThru
    )

    Assert-Windows
    if (-not $Router) {
        $alias = Get-ActiveInterfaceAlias
        $Router = (Get-NetRoute -InterfaceAlias $alias -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                   Select-Object -First 1).NextHop
        if (-not $Router) { throw 'No default gateway found. Use -Router.' }
    }
    $name = try { (Resolve-DnsName $Router -QuickTimeout -ErrorAction Stop | Select-Object -First 1).NameHost } catch { '' }
    Write-Host "`nRouter: $Router  $name" -ForegroundColor Cyan

    # Risk: High = should normally be off; Review = fine if you use it; Expected = normal router service
    $ports = @(
        @{ Port = 21;   Service = 'FTP';               Risk = 'High' }
        @{ Port = 22;   Service = 'SSH';               Risk = 'Review' }
        @{ Port = 23;   Service = 'Telnet';            Risk = 'High' }
        @{ Port = 53;   Service = 'DNS';               Risk = 'Expected' }
        @{ Port = 80;   Service = 'Web admin (HTTP)';  Risk = 'Review' }
        @{ Port = 139;  Service = 'NetBIOS/Samba';     Risk = 'Review' }
        @{ Port = 443;  Service = 'HTTPS / AiCloud';   Risk = 'Review' }
        @{ Port = 445;  Service = 'SMB file sharing';  Risk = 'Review' }
        @{ Port = 515;  Service = 'LPD printing';      Risk = 'Review' }
        @{ Port = 631;  Service = 'IPP printing';      Risk = 'Review' }
        @{ Port = 1723; Service = 'PPTP VPN';          Risk = 'High' }
        @{ Port = 3000; Service = 'Web service';       Risk = 'Review' }
        @{ Port = 5000; Service = 'UPnP/web service';  Risk = 'Review' }
        @{ Port = 7547; Service = 'TR-069 remote mgmt'; Risk = 'High' }
        @{ Port = 8080; Service = 'Alt HTTP';          Risk = 'Review' }
        @{ Port = 8443; Service = 'Web admin (HTTPS)'; Risk = 'Expected' }
        @{ Port = 9100; Service = 'Raw printing';      Risk = 'Review' }
    )

    Write-Host "`nChecking $($ports.Count) TCP ports on the LAN side..." -ForegroundColor Cyan
    $results = @($ports | ForEach-Object -ThrottleLimit 16 -Parallel {
        $p = $_
        $client = [System.Net.Sockets.TcpClient]::new()
        $open = $false
        try {
            $task = $client.ConnectAsync($using:Router, $p.Port)
            $open = $task.Wait($using:TimeoutMs) -and $client.Connected
        } catch { } finally { $client.Dispose() }
        [pscustomobject]@{ Port = $p.Port; Service = $p.Service; Open = $open; Risk = $p.Risk }
    } | Sort-Object Port)

    $results | Select-Object Port, Service, Open,
        @{ n = 'Note'; e = { Get-ServiceRiskNote -Open $_.Open -Risk $_.Risk } } | Show-Table

    $upnp = $null
    if (-not $NoUpnp) {
        Write-Host 'Checking for UPnP (SSDP)...' -ForegroundColor Cyan
        $upnp = Find-UpnpGateway -Router $Router
    }
    Write-Section 'Findings'
    $findings = @(Get-RouterFinding -Result $results -Upnp $upnp -UpnpChecked:(-not $NoUpnp))
    Save-RunFinding -Name 'Test-RouterExposure' -Finding $findings

    Write-Section 'Public IP'
    $publicIp = if ($NoPublicIp) { $null } else { try { Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 5 } catch { $null } }
    if ($NoPublicIp) {
        Write-Host '  Skipped (-NoPublicIp).'
    } elseif ($publicIp) {
        Write-Host "  Your public IP: $publicIp"
        Write-Host "  Testing it from inside your own network isn't reliable (the router loops it back)."
        Write-Host '  For the outside view, run GRC ShieldsUP (grc.com/shieldsup) or scan from a phone on cellular data.'
    } else {
        Write-Host "  Couldn't look up your public IP."
    }

    if ($Ssh) {
        if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
            throw 'OpenSSH client not found. Install it under Settings > System > Optional features.'
        }
        $outDir = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'SecurityChecks'
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        $outFile = Join-Path $outDir "RouterFirewall_$($Router)_$(Get-Date -Format 'yyyy-MM-dd_HHmm').txt"

        Write-Section "Firewall rules via SSH ($SshUser@$Router)"
        Write-Host "  You'll be asked for the router password."
        $remote = 'echo "=== FILTER ==="; iptables -S; echo; echo "=== NAT (port forwards) ==="; iptables -t nat -S; ' +
                  'echo; echo "=== IPv6 FILTER ==="; ip6tables -S 2>/dev/null'
        ssh -p $SshPort "$SshUser@$Router" $remote | Tee-Object -FilePath $outFile | Out-Host
        Write-Host "`n  Saved to: $outFile" -ForegroundColor Green
        Write-Host '  Look for: INPUT policy DROP, and DNAT rules (port forwards) you do not recognize.' -ForegroundColor Green
        Write-Host '  Turn SSH back off (or LAN only) when you are done.' -ForegroundColor Yellow
    }

    if ($PassThru) { $results }
}
