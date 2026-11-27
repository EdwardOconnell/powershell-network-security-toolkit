function Invoke-DailySecurityCheck {
    <#
    .SYNOPSIS
        All-in-one daily security check for this PC and the network it's on.
    .DESCRIPTION
        Runs, in order:
           1. Get-NetAdapterHealth   adapters, gateway, internet and DNS
           2. Get-FirewallAudit      firewall profiles and risky inbound rules
           3. Get-FirewallLog        what the firewall blocked
           4. Find-NetworkDevice     devices on the local network (flags new ones)
           5. Printers and their ports
           6. USB devices now, and Get-USBHistory (flags new USB storage)
           7. Get-HardeningStatus    the hardening baseline
           8. Get-AccountAudit       local accounts and logon settings
           9. Test-RouterExposure    router ports and UPnP
          10. Get-ThreatExposure     which threats could work on this PC
          11. Find-MalwareIndicator  signs of malware
        Then it prints a summary and the assistant's fix order. Each run saves a
        transcript, an HTML report, a CSV of program hashes and a snapshot to
        ReportDir. The snapshot is what lets the next run spot new devices.
        Read-only: it changes no settings.
    .PARAMETER InterfaceAlias
        Adapter to check. Default: the adapter carrying your internet traffic.
    .PARAMETER ActiveScan
        Ping-sweep the local subnet. Only on networks you're authorized to scan.
    .PARAMETER LogHours
        How far back to read the firewall log.
    .PARAMETER ReportDir
        Folder for reports and snapshots. Default: Documents\SecurityChecks.
    .PARAMETER NoRouter
        Skip the router port and UPnP check.
    .PARAMETER NoReport
        Save nothing (no transcript, report, hashes or snapshot).
    .PARAMETER PassThru
        Also return the list of warnings (every Risk and Warn finding as text).
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
        [string]$ReportDir = (Get-DefaultReportDir),
        [switch]$NoRouter,
        [switch]$NoReport,
        [switch]$PassThru
    )

    Assert-Administrator

    # ---------------------------------------------------------------- setup ----
    $all   = [System.Collections.Generic.List[object]]::new()   # every finding
    $extra = [System.Collections.Generic.List[object]]::new()   # findings made here, not by a sub-check
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
    # .NET file APIs resolve relative paths against the process folder, not the
    # PowerShell location, so make the path absolute first.
    $ReportDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ReportDir)
    $reportFile   = Join-Path $ReportDir "Check_$stamp.txt"
    $snapshotFile = Join-Path $ReportDir "Snapshot_$stamp.json"
    $htmlFile     = Join-Path $ReportDir "Report_$stamp.html"
    $hashFile     = Join-Path $ReportDir "Hashes_$stamp.csv"

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

    $transcribing = $false
    if (-not $NoReport) {
        New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
        try { Start-Transcript -Path $reportFile | Out-Null; $transcribing = $true }
        catch { Write-Warning "Could not start the transcript: $($_.Exception.Message)" }
    }

    $devices = @(); $usbStorage = @(); $plan = @()
    # Runs one sub-check; if it fails, the rest of the daily check still runs.
    $run = {
        param([string]$Name, [scriptblock]$Check)
        try { & $Check }
        catch { Add-Finding $extra General Info "$Name was skipped: $($_.Exception.Message)" }
    }
    try {
        Write-Host "Security check - $(Get-Date -Format 'dddd, MMMM d, yyyy h:mm tt')" -ForegroundColor Green
        Write-Host "NetSecToolkit $script:ToolkitVersion. $script:Copyright" -ForegroundColor DarkGray
        Write-Host "Computer: $env:COMPUTERNAME   User: $env:USERNAME   Network: $netName   PowerShell: $($PSVersionTable.PSVersion)"

        # ------------------------------------------------- 1. network adapters ----
        Write-Host "`n##### 1. Network adapters #####" -ForegroundColor Green
        & $run 'The adapter check' {
            $health = Get-NetAdapterHealth -PassThru
            Add-FindingRange $all $health.Findings
        }

        # --------------------------------------------------------- 2. firewall ----
        Write-Host "`n##### 2. Firewall #####" -ForegroundColor Green
        & $run 'The firewall audit' {
            $audit = Get-FirewallAudit -PassThru
            # Profile state (on, inbound default, logging) is reported by the hardening status below.
            $profilePattern = 'mpssvc|profile is DISABLED|ALLOWS inbound|not logging|Firewall audit: no issues'
            Add-FindingRange $all ($audit.Findings | Where-Object { $_.Message -notmatch $profilePattern })
        }

        # ----------------------------------------------------- 3. firewall log ----
        Write-Host "`n##### 3. Firewall log #####" -ForegroundColor Green
        try {
            $log = Get-FirewallLog -Hours $LogHours -PassThru
            Add-FindingRange $all ($log.Findings | Where-Object { $_.Message -notmatch 'Logging of blocked connections is off' })
        } catch {
            Add-Finding $extra FirewallLog Info "The firewall log check was skipped: $($_.Exception.Message)"
        }

        # ------------------------------------------------- 4. network devices ----
        Write-Host "`n##### 4. Devices on the local network ($InterfaceAlias) #####" -ForegroundColor Green
        try {
            $devices = @(Find-NetworkDevice -InterfaceAlias $InterfaceAlias -Passive:(-not $ActiveScan) -PassThru | Where-Object { $_ })
        } catch {
            Add-Finding $extra Devices Info "The device list was skipped: $($_.Exception.Message)"
        }
        if ($devices.Count) {
            Write-Section 'New devices'
            if ($prevSnap) {
                $knownMacs = @($prevSnap.NetworkDevices | ForEach-Object MAC)
                $new = @($devices | Where-Object { $_.MAC -and $_.MAC -notin $knownMacs -and $_.Role -ne 'This PC' })
                if (-not $new.Count) {
                    Add-Finding $extra Devices OK "No new devices on '$netName' since the last check ($($prevSnap.Date))."
                }
                foreach ($d in $new) {
                    $who = @($d.IP, $d.MAC, $d.Hostname | Where-Object { $_ }) -join ' '
                    if ($d.RandomMAC) {
                        Add-Finding $extra Devices Info "New device since $($prevSnap.Date): $who. Randomized MAC: likely a phone or laptop."
                    } else {
                        Add-Finding $extra Devices Warn "New device with a fixed MAC on '$netName' since $($prevSnap.Date): $who." "If you do not recognize it, check the router's client list"
                    }
                }
            } else {
                Add-Finding $extra Devices Info "First check on '$netName'. This device list is saved as the baseline."
            }
        }

        # --------------------------------------------------------- 5. printers ----
        Write-Host "`n##### 5. Printers #####" -ForegroundColor Green
        Get-Printer -ErrorAction SilentlyContinue | Select-Object Name, PortName, DriverName | Show-Table

        # ------------------------------------------------------------- 6. USB ----
        Write-Host "`n##### 6. USB #####" -ForegroundColor Green
        Write-Section 'USB devices connected now'
        $usbNow = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
            Where-Object { $_.InstanceId -match '^(USB|USBSTOR|USBPRINT)\\' -and
                           $_.FriendlyName -notmatch 'Hub|Host Controller|Composite' })
        $usbNow | Sort-Object Class, FriendlyName |
            Select-Object Class, FriendlyName, Status,
                @{ n = 'Note'; e = { if (Test-DeviceDisabled $_) { 'Disabled' } } },
                @{ n = 'VendorID'; e = { if ($_.InstanceId -match 'VID_([0-9A-F]{4})') { $Matches[1] } } } |
            Show-Table
        foreach ($u in ($usbNow | Where-Object { $_.Status -ne 'OK' -and -not (Test-DeviceDisabled $_) })) {
            Add-Finding $extra USB Warn "USB device problem: $($u.FriendlyName) ($($u.Status))" 'Device Manager: check the device, replug it or update its driver'
        }

        try {
            $usbResult = Get-USBHistory -PassThru
            Add-FindingRange $all $usbResult.Findings
            # Snapshots store the full instance key as Serial (the 1.x format), so old snapshots still compare.
            $usbStorage = @($usbResult.Devices | ForEach-Object { [pscustomobject]@{ Device = $_.Device; Serial = $_.InstanceId } })
        } catch {
            Add-Finding $extra USB Info "The USB history was skipped: $($_.Exception.Message)"
        }
        # Test for the property, not its value: the first USB drive after an
        # empty baseline must still be flagged.
        if ($latestSnap -and $latestSnap.PSObject.Properties['UsbStorage']) {
            $knownSerials = @($latestSnap.UsbStorage | ForEach-Object Serial)
            $newUsb = @($usbStorage | Where-Object { $_.Serial -notin $knownSerials })
            foreach ($u in $newUsb) {
                Add-Finding $extra USB Warn "USB storage device connected since the last check ($($latestSnap.Date)): $($u.Device), serial $($u.Serial -replace '&\d+$', '')." 'If nobody you know plugged it in, find out who did'
            }
            if (-not $newUsb.Count) { Add-Finding $extra USB OK "No new USB storage devices since the last check ($($latestSnap.Date))." }
        }

        # ------------------------------------------- 7-11. the newer audits ----
        Write-Host "`n##### 7. Hardening status #####" -ForegroundColor Green
        & $run 'The hardening status' { Add-FindingRange $all (Get-HardeningStatus -PassThru) }

        Write-Host "`n##### 8. Accounts and logon #####" -ForegroundColor Green
        & $run 'The account audit' {
            $acct = Get-AccountAudit -PassThru
            Add-FindingRange $all $acct.Findings
        }

        if (-not $NoRouter) {
            Write-Host "`n##### 9. Router #####" -ForegroundColor Green
            & $run 'The router check' {
                Test-RouterExposure -NoPublicIp
                Add-FindingRange $all $script:LastRun['Test-RouterExposure']
            }
        }

        Write-Host "`n##### 10. Threat exposure #####" -ForegroundColor Green
        & $run 'The threat rating' {
            $exposure = Get-ThreatExposure -PassThru
            Add-FindingRange $all $exposure.Findings
        }

        Write-Host "`n##### 11. Signs of malware #####" -ForegroundColor Green
        & $run 'The malware indicator check' {
            $export = if ($NoReport) { '' } else { $hashFile }
            $mal = Find-MalwareIndicator -ExportPath $export -PassThru
            Add-FindingRange $all $mal.Findings
        }

        Add-FindingRange $all $extra

        # ---------------------------------------------------------- summary ----
        Write-Host "`n##### Summary #####" -ForegroundColor Green
        $c = Get-FindingCount $all
        $color = if ($c.Risk) { 'Red' } elseif ($c.Warn) { 'Yellow' } else { 'Green' }
        Write-Host "  $($c.Risk) risk(s), $($c.Warn) warning(s), $($c.Total) finding(s) in total." -ForegroundColor $color
        foreach ($f in @($all | Where-Object Level -eq 'Risk') + @($all | Where-Object Level -eq 'Warn')) {
            Write-Host ('  [{0,-4}] {1}: {2}' -f $f.Level, $f.Area, $f.Message) -ForegroundColor $(if ($f.Level -eq 'Risk') { 'Red' } else { 'Yellow' })
        }
        if (-not ($c.Risk + $c.Warn)) { Write-Host '  No issues found.' -ForegroundColor Green }

        Write-Section 'What to fix first (assistant)'
        $plan = @(Get-AssistantFixPlan -Finding $all)
        foreach ($step in $plan) { Write-Wrapped -Text $step -Indent 2 }
        Write-Host "`n  Ask about any of it: Invoke-NetSecAssistant" -ForegroundColor DarkGray
    } finally {
        if ($transcribing) {
            try { Stop-Transcript | Out-Null } catch { Write-Verbose 'The transcript was already stopped.' }
        }
    }

    # The assistant now explains exactly what this run reported, without the
    # overlap between the firewall audit and the hardening status.
    $script:LastRun = @{ 'Invoke-DailySecurityCheck' = $all.ToArray() }

    if (-not $NoReport) {
        # Keep every device seen on this network so far, not just this run: an
        # idle phone missing from one run must not come back as "new" on the next.
        $baseline = @($devices | Select-Object IP, MAC, Hostname, RandomMAC)
        if ($prevSnap) {
            $seenMacs = @($baseline | ForEach-Object MAC)
            foreach ($old in @($prevSnap.NetworkDevices)) {
                if ($old -and $old.MAC -and $old.MAC -notin $seenMacs) { $baseline += ($old | Select-Object IP, MAC, Hostname, RandomMAC) }
            }
        }
        [pscustomobject]@{
            Date           = (Get-Date).ToString('yyyy-MM-dd HH:mm')
            Network        = $netName
            NetworkDevices = @($baseline)
            UsbStorage     = @($usbStorage)
        } | ConvertTo-Json -Depth 4 | Set-Content -Path $snapshotFile -Encoding utf8

        $notes = @("Computer $env:COMPUTERNAME, network '$netName', $((Get-Date).ToString('yyyy-MM-dd HH:mm')).")
        Export-FindingHtml -Finding $all -Path $htmlFile -Title "Security check $stamp" -Note $notes -Plan $plan

        Write-Host "`nSaved to $ReportDir" -ForegroundColor Green
        Write-Host "  Report_$stamp.html (open in a browser), Check_$stamp.txt, Snapshot_$stamp.json, Hashes_$stamp.csv" -ForegroundColor Green
    }

    if ($PassThru) {
        @($all | Where-Object { $_.Level -in 'Risk', 'Warn' } | ForEach-Object { "$($_.Area): $($_.Message)" })
    }
}
