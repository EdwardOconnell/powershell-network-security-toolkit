function Invoke-DailySecurityCheck {
    <#
    .SYNOPSIS
        All-in-one daily security check for this PC and the network it's on.
    .DESCRIPTION
        Checks, in order:
          1. Network adapters, gateway, internet and DNS
          2. Firewall service, profiles, logging, risky inbound rules
          3. Firewall log: drops aimed at this PC, and traffic from outside your subnet
          4. Devices on the local network (flags devices not seen on your last check)
          5. Printers and their ports
          6. USB devices now, and USB storage ever connected (flags new ones)
          7. Summary of everything flagged
        Each run saves a text report and a snapshot to ReportDir. The snapshot is what lets
        the next run spot new devices. Read-only: it changes no settings.
    .PARAMETER InterfaceAlias
        Adapter to check. Default: the adapter carrying your internet traffic.
    .PARAMETER ActiveScan
        Ping-sweep the local subnet. Only on networks you're authorized to scan.
    .PARAMETER LogHours
        How far back to read the firewall log.
    .PARAMETER ReportDir
        Folder for reports and snapshots.
    .PARAMETER PassThru
        Also return the list of warnings.
    .EXAMPLE
        Invoke-DailySecurityCheck
    .EXAMPLE
        Invoke-DailySecurityCheck -ActiveScan -LogHours 72
    #>
    [CmdletBinding()]
    param(
        [string]$InterfaceAlias,
        [switch]$ActiveScan,
        [ValidateRange(1, 720)][int]$LogHours = 24,
        [string]$ReportDir = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'SecurityChecks'),
        [switch]$PassThru
    )

    Assert-Administrator
    function Add-Warning([string]$Text) { $warnings.Add($Text) }

    # ---------------------------------------------------------------- setup ----
    $warnings = [System.Collections.Generic.List[string]]::new()
    $stamp    = Get-Date -Format 'yyyy-MM-dd_HHmm'
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
    $reportFile   = Join-Path $ReportDir "Check_$stamp.txt"
    $snapshotFile = Join-Path $ReportDir "Snapshot_$stamp.json"

    # Pick the connected adapter with the best default route (works on Wi-Fi, 'Wi-Fi 2', Ethernet, etc.)
    if (-not $InterfaceAlias) {
        $InterfaceAlias = Get-ActiveInterfaceAlias
        if (-not $InterfaceAlias) { $InterfaceAlias = 'Wi-Fi' }
    }

    $netName = (Get-NetConnectionProfile -InterfaceAlias $InterfaceAlias -ErrorAction SilentlyContinue |
                Select-Object -First 1).Name

    # Most recent snapshot overall (for USB), and most recent on this same network (for devices)
    $latestSnap = $null; $prevSnap = $null
    foreach ($file in (Get-ChildItem $ReportDir -Filter 'Snapshot_*.json' -ErrorAction SilentlyContinue |
                       Sort-Object Name -Descending)) {
        try { $s = Get-Content $file.FullName -Raw | ConvertFrom-Json } catch { continue }
        if (-not $latestSnap) { $latestSnap = $s }
        if ($netName -and $s.Network -eq $netName) { $prevSnap = $s; break }
    }

    Start-Transcript -Path $reportFile | Out-Null
    try {
        Write-Host "Security check - $(Get-Date -Format 'dddd, MMMM d, yyyy h:mm tt')" -ForegroundColor Green
        Write-Host "Computer: $env:COMPUTERNAME   User: $env:USERNAME   Network: $netName   PowerShell: $($PSVersionTable.PSVersion)"

        # ------------------------------------------------- 1. network adapters ----
        Write-Section "1. Network adapters"
        $adapterRows = foreach ($a in Get-NetAdapter) {
            $cfg = if ($a.Status -ne 'Not Present') {
                Get-NetIPConfiguration -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue
            }
            $ip  = $cfg.IPv4Address.IPAddress | Select-Object -First 1
            $gw  = $cfg.IPv4DefaultGateway.NextHop | Select-Object -First 1
            $gwPing = if ($gw) {
                Test-Connection -TargetName $gw -Count 1 -TimeoutSeconds 2 -Quiet -ErrorAction SilentlyContinue
            } else { $null }

            if ($a.Status -eq 'Up' -and $ip -like '169.254*') {
                Add-Warning "$($a.Name) has no DHCP lease (APIPA address $ip)."
            }
            if ($a.Status -eq 'Up' -and $gw -and -not $gwPing) {
                Add-Warning "$($a.Name): gateway $gw did not answer ping."
            }
            [pscustomobject]@{
                Name = $a.Name; Status = $a.Status; Speed = $a.LinkSpeed
                IPv4 = $ip; Gateway = $gw; GW_Ping = $gwPing
            }
        }
        $adapterRows | Show-Table


        foreach ($d in @(Get-PnpDevice -Class Net -PresentOnly -ErrorAction SilentlyContinue |
                         Where-Object { $_.Status -eq 'Error' -and -not (Test-DeviceDisabled $_) })) {
            Add-Warning "Network adapter driver problem: $($d.FriendlyName)"
        }

        $inet = [pscustomobject]@{
            'Ping 8.8.8.8' = Test-Connection -TargetName 8.8.8.8 -Count 1 -TimeoutSeconds 2 -Quiet -ErrorAction SilentlyContinue
            'DNS lookup'   = $(try { [bool](Resolve-DnsName google.com -Type A -QuickTimeout -ErrorAction Stop) } catch { $false })
            'HTTPS 443'    = Test-NetConnection google.com -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
        }
        $inet | Show-Table
        if (-not $inet.'DNS lookup') { Add-Warning "DNS lookups are failing." }
        if (-not $inet.'HTTPS 443')  { Add-Warning "No HTTPS connectivity to the internet." }

        # --------------------------------------------------------- 2. firewall ----
        Write-Section "2. Firewall"
        $svc = Get-Service -Name mpssvc
        Write-Host "  Service: $($svc.Status) ($($svc.StartType))"
        if ($svc.Status -ne 'Running') { Add-Warning "Firewall service (mpssvc) is $($svc.Status)." }

        $profiles = Get-NetFirewallProfile -PolicyStore ActiveStore
        $profiles |
            Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogBlocked, LogMaxSizeKilobytes |
            Show-Table
        foreach ($p in $profiles) {
            if ("$($p.Enabled)" -ne 'True')              { Add-Warning "$($p.Name) firewall profile is DISABLED." }
            if ("$($p.DefaultInboundAction)" -eq 'Allow') { Add-Warning "$($p.Name) profile ALLOWS inbound traffic by default." }
            if ("$($p.LogBlocked)" -ne 'True')           { Add-Warning "$($p.Name) profile is not logging blocked connections." }
        }

        Write-Host "  Active networks:"
        Get-NetConnectionProfile |
            Select-Object InterfaceAlias, Name, NetworkCategory, IPv4Connectivity |
            Show-Table

        $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow)
        $portIdx = @{}; $addrIdx = @{}; $appIdx = @{}
        Get-NetFirewallPortFilter        -PolicyStore ActiveStore -All | ForEach-Object { $portIdx[$_.InstanceID] = $_ }
        Get-NetFirewallAddressFilter     -PolicyStore ActiveStore -All | ForEach-Object { $addrIdx[$_.InstanceID] = $_ }
        Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -All | ForEach-Object { $appIdx[$_.InstanceID]  = $_ }

        $ruleInfo = @(foreach ($r in $rules) {
            $id = $r.InstanceID ?? $r.Name
            $pf = $portIdx[$id]; $af = $addrIdx[$id]; $apf = $appIdx[$id]
            [pscustomobject]@{
                Name       = $r.DisplayName
                Profile    = "$($r.Profile)"
                Protocol   = $pf.Protocol
                LocalPort  = $pf.LocalPort -join ','
                RemoteAddr = $af.RemoteAddress -join ','
                Program    = $apf.Program
                Risky      = @(Get-RiskyPortMatch -Ports $pf.LocalPort) -join ', '
            }
        })
        Write-Host "  $($ruleInfo.Count) enabled inbound allow rules."

        Write-Host "`n  Rules exposing commonly attacked ports:" -ForegroundColor Yellow
        $risky = @($ruleInfo | Where-Object Risky)
        $risky | Select-Object Name, Profile, Protocol, LocalPort, RemoteAddr, Risky | Show-Table
        foreach ($r in ($risky | Where-Object RemoteAddr -eq 'Any')) {
            Add-Warning "Firewall rule '$($r.Name)' opens $($r.Risky) to ANY address ($($r.Profile) profile)."
        }

        Write-Host "  Allowed programs in user-writable folders:" -ForegroundColor Yellow
        $userPath = '\\Users\\|\\Temp\\|%(APPDATA|LOCALAPPDATA|TEMP|TMP|USERPROFILE)%'
        $suspect  = @($ruleInfo | Where-Object { $_.Program -match $userPath })
        $suspect | Select-Object Name, Profile, Program | Show-Table
        if ($suspect.Count) {
            Add-Warning "$($suspect.Count) inbound rule(s) allow programs in user folders. Review section 2."
        }

        # ----------------------------------------------------- 3. firewall log ----
        Write-Section "3. Firewall log (last $LogHours hours)"
        $logPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"

        $myIPs = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                   Where-Object IPAddress -ne '127.0.0.1' | Select-Object -ExpandProperty IPAddress)
        $localNets = @(foreach ($a in (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                       Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254*' })) {
            $m = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $a.PrefixLength))
            [pscustomobject]@{ Net = [uint32]((ConvertTo-UInt32 $a.IPAddress) -band $m); Mask = $m }
        })

        $srcCache = @{}
        function Test-LocalSource([string]$ip) {
            if ($srcCache.ContainsKey($ip)) { return $srcCache[$ip] }
            $result = $false
            try {
                $n = ConvertTo-UInt32 $ip
                foreach ($ln in $localNets) {
                    if (($n -band $ln.Mask) -eq $ln.Net) { $result = $true; break }
                }
            } catch { $result = $true }   # unparseable address: don't flag it
            $srcCache[$ip] = $result
            $result
        }

        if (-not (Test-Path $logPath)) {
            Write-Host "  No firewall log found. Blocked-connection logging may be off."
        } else {
            $cutoff    = (Get-Date).AddHours(-$LogHours)
            $direct    = [System.Collections.Generic.List[object]]::new()
            $offSubnet = @{}
            $dropCount = 0

            # The firewall service keeps the log open for writing, so open it with ReadWrite
            # sharing (the same way Get-Content does); a plain read-only open gets "in use".
            $fs = $null; $sr = $null
            try {
                $fs = [System.IO.FileStream]::new($logPath, [System.IO.FileMode]::Open,
                          [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                $sr = [System.IO.StreamReader]::new($fs)
                while ($null -ne ($line = $sr.ReadLine())) {
                    $entry = ConvertFrom-FirewallLogLine -Line $line
                    if (-not $entry -or $entry.Action -ne 'DROP' -or $entry.Time -lt $cutoff) { continue }
                    $dropCount++
                    if ($entry.Destination -in $myIPs) {
                        $direct.Add([pscustomobject]@{ Time = $entry.Time; Source = $entry.Source; Protocol = $entry.Protocol; DestPort = $entry.DestPort })
                    }
                    $src = $entry.Source
                    if ($src -notmatch ':' -and $src -ne '0.0.0.0' -and $src -notin $myIPs -and -not (Test-LocalSource $src)) {
                        $offSubnet[$src] = $entry.Time
                    }
                }
            } catch {
                Write-Host "  Could not read the firewall log: $($_.Exception.Message)" -ForegroundColor Yellow
                Add-Warning "The firewall log could not be read, so section 3 is incomplete."
            } finally {
                if ($sr) { $sr.Dispose() }
                if ($fs) { $fs.Dispose() }
            }

            Write-Host "  Blocked packets in this window: $dropCount  (aimed directly at this PC: $($direct.Count))"

            Write-Host "`n  Drops aimed directly at this PC:" -ForegroundColor Yellow
            $direct |
                Group-Object Source, Protocol, DestPort |
                Sort-Object Count -Descending |
                Select-Object -First 15 Count,
                    @{ n = 'Source, Protocol, Port'; e = { $_.Name } },
                    @{ n = 'LastSeen'; e = { ($_.Group | Measure-Object Time -Maximum).Maximum } } |
                Show-Table
            if ($direct.Count) {
                Add-Warning "$($direct.Count) blocked packet(s) were aimed directly at this PC. Review section 3."
            }

            Write-Host "  Traffic from addresses outside your local subnet:" -ForegroundColor Yellow
            $offSubnet.GetEnumerator() |
                ForEach-Object { [pscustomobject]@{ Source = $_.Key; LastSeen = $_.Value } } |
                Sort-Object LastSeen -Descending |
                Show-Table
            if ($offSubnet.Count) {
                Add-Warning "Traffic from outside your subnet: $($offSubnet.Keys -join ', ')"
            }
        }

        # ------------------------------------------------- 4. network devices ----
        Write-Section "4. Devices on the local network ($InterfaceAlias)"
        $devices = @()
        $ipInfo = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                  Where-Object { $_.IPAddress -notlike '169.254*' } | Select-Object -First 1

        if (-not $ipInfo) {
            Write-Host "  '$InterfaceAlias' has no usable IPv4 address. Skipping."
        } else {
            $myIP   = $ipInfo.IPAddress
            $prefix = $ipInfo.PrefixLength
            $gw     = (Get-NetRoute -InterfaceAlias $InterfaceAlias -DestinationPrefix '0.0.0.0/0' `
                         -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
            $myMac  = (Get-NetAdapter -Name $InterfaceAlias).MacAddress

            $range = Get-SubnetRange -IPAddress $myIP -PrefixLength $ipInfo.PrefixLength
            $network = ConvertTo-UInt32 $range.Network
            $prefix  = $range.Prefix
            $first   = $range.First
            $last    = $range.Last
            $mode  = if ($ActiveScan) { 'active ping sweep' } else { 'passive, neighbor table only' }
            Write-Host "  Range: $(ConvertTo-IPAddressString $network)/$prefix   Mode: $mode"

            $pingReplies = @()
            if ($ActiveScan) {
                $targets = for ($i = [uint64]$first; $i -le $last; $i++) {
                    $t = ConvertTo-IPAddressString ([uint32]$i)
                    if ($t -ne $myIP) { $t }
                }
                $pingReplies = @($targets | ForEach-Object -ThrottleLimit 64 -Parallel {
                    $p = [System.Net.NetworkInformation.Ping]::new()
                    try { if ($p.Send($_, 500).Status -eq 'Success') { $_ } } catch { } finally { $p.Dispose() }
                })
            }

            $neighbors = @{}
            Get-NetNeighbor -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.State -notin 'Unreachable', 'Incomplete', 'Permanent' -and
                    $_.LinkLayerAddress -notin '00-00-00-00-00-00', 'FF-FF-FF-FF-FF-FF', ''
                } |
                ForEach-Object {
                    $n = ConvertTo-UInt32 $_.IPAddress
                    if ($n -ge $first -and $n -le $last) { $neighbors[$_.IPAddress] = $_ }
                }

            $allIPs = @($pingReplies) + @($neighbors.Keys) + @($myIP) | Sort-Object -Unique
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
                    ARPState  = if ($ip -eq $myIP) { 'Self' } else { "$($nb.State)" }
                }
            }
            $devices = @($devices | Sort-Object { ConvertTo-UInt32 $_.IP })

            Write-Host "  Devices found: $($devices.Count)"
            $devices | Show-Table

            if ($prevSnap) {
                $knownMacs = @($prevSnap.NetworkDevices | ForEach-Object MAC)
                $new = @($devices | Where-Object { $_.MAC -and $_.MAC -notin $knownMacs -and $_.Role -ne 'This PC' })
                if ($new.Count) {
                    Write-Host "  New since last check on this network ($($prevSnap.Date)):" -ForegroundColor Yellow
                    $new | Select-Object IP, Hostname, MAC, RandomMAC | Show-Table
                    $newFixed = @($new | Where-Object { -not $_.RandomMAC })
                    if ($newFixed.Count) {
                        Add-Warning "$($newFixed.Count) new device(s) with a fixed MAC on '$netName'. Review section 4."
                    }
                } else {
                    Write-Host "  No new devices since last check ($($prevSnap.Date))."
                }
            } else {
                Write-Host "  First check on '$netName'. This device list is saved as the baseline." -ForegroundColor Yellow
            }
        }

        # --------------------------------------------------------- 5. printers ----
        Write-Section "5. Printers"
        Get-Printer -ErrorAction SilentlyContinue | Select-Object Name, PortName, DriverName | Show-Table

        # ------------------------------------------------------------- 6. USB ----
        Write-Section "6. USB devices connected now"
        $usbNow = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
            Where-Object { $_.InstanceId -match '^(USB|USBSTOR|USBPRINT)\\' -and
                           $_.FriendlyName -notmatch 'Hub|Host Controller|Composite' })
        $usbNow | Sort-Object Class, FriendlyName |
            Select-Object Class, FriendlyName, Status,
                @{ n = 'Note'; e = { if (Test-DeviceDisabled $_) { 'Disabled' } } },
                @{ n = 'VendorID'; e = { if ($_.InstanceId -match 'VID_([0-9A-F]{4})') { $Matches[1] } } } |
            Show-Table
        foreach ($u in ($usbNow | Where-Object { $_.Status -ne 'OK' -and -not (Test-DeviceDisabled $_) })) {
            Add-Warning "USB device problem: $($u.FriendlyName) ($($u.Status))"
        }

        Write-Section "USB storage devices ever connected"
        $usbStorage = @(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction SilentlyContinue |
            Where-Object FriendlyName |
            ForEach-Object { [pscustomobject]@{ Device = $_.FriendlyName; Serial = $_.PSChildName } })
        $usbStorage | Show-Table

        if ($latestSnap) {
            $knownSerials = @($latestSnap.UsbStorage | ForEach-Object Serial)
            $newUsb = @($usbStorage | Where-Object { $_.Serial -notin $knownSerials })
            if ($newUsb.Count) {
                Write-Host "  New since last check ($($latestSnap.Date)):" -ForegroundColor Yellow
                $newUsb | Show-Table
                Add-Warning "$($newUsb.Count) USB storage device(s) connected since the last check. Review section 6."
            } else {
                Write-Host "  No new USB storage devices since last check ($($latestSnap.Date))."
            }
        }

        # ---------------------------------------------------------- summary ----
        Write-Section "Summary"
        if ($warnings.Count) {
            $warnings | ForEach-Object { Write-Host "[!] $_" -ForegroundColor Red }
        } else {
            Write-Host "No issues found." -ForegroundColor Green
        }

        [pscustomobject]@{
            Date           = (Get-Date).ToString('yyyy-MM-dd HH:mm')
            Network        = $netName
            NetworkDevices = @($devices | Select-Object IP, MAC, Hostname, RandomMAC)
            UsbStorage     = @($usbStorage)
        } | ConvertTo-Json -Depth 4 | Set-Content -Path $snapshotFile -Encoding utf8

    } finally {
        Stop-Transcript | Out-Null
    }
    Write-Host "`nReport saved to: $reportFile" -ForegroundColor Green
    if ($PassThru) { $warnings.ToArray() }
}
