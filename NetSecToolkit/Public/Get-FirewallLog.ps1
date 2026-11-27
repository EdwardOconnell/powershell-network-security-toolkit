function Get-FirewallLog {
    <#
    .SYNOPSIS
        Summarizes what Windows Firewall blocked, from pfirewall.log.
    .DESCRIPTION
        Reads pfirewall.log (and pfirewall.log.old after a rollover) for the last
        -Hours, counts dropped packets, lists the sources that tried to reach this PC
        directly, flags likely port scans (one source, 10+ ports) and blocked traffic
        from the internet or from outside your subnet.
        Needs logging of blocked connections (Set-FirewallBaseline or
        Set-HardeningBaseline turns it on) and an Administrator window to read the
        log. Changes nothing.
    .PARAMETER Hours
        How far back to read. Default 24.
    .PARAMETER Path
        Log file. Default: the log file(s) of the firewall profiles.
    .PARAMETER Top
        How many source rows to show.
    .PARAMETER PassThru
        Also return the drops aimed at this PC, the off-subnet sources and the findings.
    .EXAMPLE
        Get-FirewallLog -Hours 72
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(1, 720)][int]$Hours = 24,
        [string]$Path,
        [ValidateRange(1, 100)][int]$Top = 15,
        [switch]$PassThru
    )

    Assert-Windows
    $findings = [System.Collections.Generic.List[object]]::new()
    Write-Section "Firewall log (last $Hours hours)"

    $paths = [System.Collections.Generic.List[string]]::new()
    if ($Path) {
        $paths.Add($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
    } else {
        $fw = Get-FirewallState
        foreach ($p in @($fw.Profiles)) {
            if ($p.LogFileName) {
                $full = [Environment]::ExpandEnvironmentVariables($p.LogFileName)
                if ($full -notin $paths) { $paths.Add($full) }
            }
        }
        if (-not $paths.Count) { $paths.Add("$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log") }
        $notLogging = @($fw.Profiles | Where-Object { -not $_.LogBlocked } | ForEach-Object Name)
        if ($notLogging.Count) {
            Add-Finding $findings FirewallLog Warn "Logging of blocked connections is off for: $($notLogging -join ', '). There may be no blocked traffic to review." 'Set-FirewallBaseline'
        }
    }
    $files = @(foreach ($f in $paths) { foreach ($c in "$f.old", $f) { if (Test-Path -LiteralPath $c) { $c } } })

    $direct    = [System.Collections.Generic.List[object]]::new()
    $offSubnet = @{}
    $drops     = 0

    if (-not $files.Count) {
        Add-Finding $findings FirewallLog Info "No firewall log found at $($paths -join ', '). Logging of blocked connections may be off."
    } else {
        $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        $myIPs = @($addresses | Where-Object IPAddress -ne '127.0.0.1' | ForEach-Object IPAddress)
        $localNets = @(foreach ($a in ($addresses | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254*' })) {
            $m = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $a.PrefixLength))
            [pscustomobject]@{ Net = [uint32]((ConvertTo-UInt32 $a.IPAddress) -band $m); Mask = $m }
        })
        $cutoff = (Get-Date).AddHours(-$Hours)
        $localCache = @{}

        foreach ($file in $files) {
            try {
                foreach ($line in (Read-SharedTextFile -Path $file)) {
                    # Cheap string check first: a busy log holds tens of thousands of lines.
                    if (-not $line -or $line.IndexOf(' DROP ') -lt 0) { continue }
                    $e = ConvertFrom-FirewallLogLine -Line $line
                    if (-not $e -or $e.Action -ne 'DROP' -or $e.Time -lt $cutoff) { continue }
                    $drops++
                    if ($e.Destination -in $myIPs) { $direct.Add($e) }
                    $src = $e.Source
                    if ($src -match $script:Ipv4Pattern -and $src -ne '0.0.0.0' -and $src -notin $myIPs) {
                        if (-not $localCache.ContainsKey($src)) { $localCache[$src] = Test-InLocalNetwork -Address $src -Network $localNets }
                        if (-not $localCache[$src]) { $offSubnet[$src] = $e.Time }
                    }
                }
            } catch {
                Add-Finding $findings FirewallLog Info "Could not read ${file}: $($_.Exception.Message) Run as administrator."
            }
        }

        Write-Host "  Log: $($files -join ', ')"
        Write-Host "  Blocked packets: $drops   aimed at this PC: $($direct.Count)"

        if ($direct.Count) {
            Write-Host "`n  Blocked connections aimed at this PC, by source:" -ForegroundColor Yellow
            $direct | Group-Object Source | Sort-Object Count -Descending | Select-Object -First $Top | ForEach-Object {
                $ports = @($_.Group | ForEach-Object { "$($_.Protocol)/$($_.DestPort)" } | Sort-Object -Unique)
                $portText = @($ports | Select-Object -First 6) -join ' '
                if ($ports.Count -gt 6) { $portText += " +$($ports.Count - 6) more" }
                [pscustomobject]@{
                    Count    = $_.Count
                    Source   = $_.Name
                    From     = if ($_.Name -notmatch $script:Ipv4Pattern) { 'IPv6' } elseif (Test-PrivateIPv4 $_.Name) { 'private' } else { 'INTERNET' }
                    LastSeen = ($_.Group | Measure-Object Time -Maximum).Maximum
                    Ports    = $portText
                }
            } | Show-Table
        }
        if ($offSubnet.Count) {
            Write-Host '  Blocked traffic from addresses outside your local subnet:' -ForegroundColor Yellow
            $offSubnet.GetEnumerator() |
                ForEach-Object { [pscustomobject]@{ Source = $_.Key; LastSeen = $_.Value } } |
                Sort-Object LastSeen -Descending | Select-Object -First $Top | Show-Table
        }

        if (-not $drops) {
            Add-Finding $findings FirewallLog OK "No blocked packets in the last $Hours hours."
        } else {
            Add-Finding $findings FirewallLog Info "$drops packet(s) blocked in the last $Hours hours; $($direct.Count) aimed at this PC, the rest broadcast or multicast."
        }

        # One source probing many ports looks like a scan.
        foreach ($g in @($direct | Group-Object Source)) {
            $ports = @($g.Group | ForEach-Object { "$($_.DestPort)" } | Sort-Object -Unique)
            if ($ports.Count -ge 10) {
                Add-Finding $findings FirewallLog Warn "Possible port scan: $($g.Name) tried $($ports.Count) different ports on this PC." 'Find-NetworkDevice to identify the device; if it is not yours, remove it from the network'
            }
        }

        $publicDirect = @($direct | Where-Object { $_.Source -match $script:Ipv4Pattern -and -not (Test-PrivateIPv4 $_.Source) } |
            ForEach-Object Source | Sort-Object -Unique)
        if ($publicDirect.Count) {
            $shown = @($publicDirect | Select-Object -First 5) -join ', '
            Add-Finding $findings FirewallLog Warn "Blocked traffic from the internet reached this PC directly ($($publicDirect.Count) address(es): $shown). The router may forward ports or use DMZ for this PC, or this PC has a public address." 'Check the router for port forwards / DMZ pointing at this PC; Test-RouterExposure'
        }

        $localDirect = @($direct | Where-Object { Test-PrivateIPv4 $_.Source }).Count
        if ($localDirect) {
            Add-Finding $findings FirewallLog Info "$localDirect blocked packet(s) from private addresses were aimed at this PC (usually discovery traffic from other devices)."
        }

        $offPrivate = @($offSubnet.Keys | Where-Object { Test-PrivateIPv4 $_ } | Sort-Object)
        if ($offPrivate.Count) {
            Add-Finding $findings FirewallLog Info "Blocked traffic from private addresses outside your subnet: $(@($offPrivate | Select-Object -First 8) -join ', ')"
        }
    }

    Save-RunFinding -Name 'Get-FirewallLog' -Finding $findings
    if ($PassThru) {
        [pscustomobject]@{
            Drops = $drops; Direct = $direct.ToArray(); OffSubnet = @($offSubnet.Keys | Sort-Object); Findings = $findings.ToArray()
        }
    }
}
