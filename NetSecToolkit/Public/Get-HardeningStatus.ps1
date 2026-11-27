function Get-HardeningStatus {
    <#
    .SYNOPSIS
        Read-only check of this PC against the hardening baseline.
    .DESCRIPTION
        Checks the firewall, Remote Desktop and Remote Assistance, the services
        Set-HardeningBaseline disables, SMBv1, NetBIOS, the Guest account, AutoRun,
        anonymous access, LM hashes, NTLMv2, the password and lockout policy, UAC, DEP,
        how recently Windows was updated, and which TCP ports are listening on the
        network. Each result is a finding: OK, Info, Warn or Risk, with the fix.
        Changes nothing. Run it elevated to read every setting.
    .PARAMETER PassThru
        Also return the findings as objects.
    .EXAMPLE
        Get-HardeningStatus
    .EXAMPLE
        Get-HardeningStatus -PassThru | Where-Object Level -in 'Risk', 'Warn'
    #>
    [CmdletBinding()]
    param([switch]$PassThru)

    Assert-Windows
    $findings = [System.Collections.Generic.List[object]]::new()
    $fix      = $script:HardeningFix
    $isAdmin  = Test-IsAdministrator
    if (-not $isAdmin) {
        Write-Finding -Level Info -Message 'Not an Administrator window: some settings may not be readable.'
    }

    # --------------------------------------------------------------- firewall ----
    Write-Section 'Firewall'
    $fw = Get-FirewallState
    if ($fw.Error) {
        $level = if ($isAdmin) { 'Risk' } else { 'Info' }
        Add-Finding $findings Firewall $level "Could not read the firewall policy: $($fw.Error)" 'Run this in an Administrator window'
    } else {
        if ($fw.ServiceRunning) { Add-Finding $findings Firewall OK 'The firewall service is running.' }
        else { Add-Finding $findings Firewall Risk 'The firewall service (mpssvc) is NOT running.' 'Start-Service mpssvc; Set-Service mpssvc -StartupType Automatic' }
        foreach ($p in $fw.Profiles) {
            if ($p.Enabled) { Add-Finding $findings Firewall OK "$($p.Name) firewall profile is on." }
            else { Add-Finding $findings Firewall Risk "$($p.Name) firewall profile is OFF." $fix }
            if ($p.InboundAllow) {
                Add-Finding $findings Firewall Risk "$($p.Name) profile ALLOWS inbound connections by default." $fix
            }
            if ($p.LogBlocked) { Add-Finding $findings Firewall OK "$($p.Name) profile logs blocked connections." }
            else { Add-Finding $findings Firewall Warn "$($p.Name) profile is not logging blocked connections." $fix }
        }
    }

    # ---------------------------------------------------------- remote access ----
    Write-Section 'Remote access'
    $deny = Get-RegValue -Path $script:TsPath -Name 'fDenyTSConnections'
    $rdpOn = ($null -ne $deny -and [int]$deny -eq 0)
    if (-not $rdpOn) {
        Add-Finding $findings Remote OK 'Remote Desktop is off.'
    } else {
        Add-Finding $findings Remote Warn 'Remote Desktop is on.' "$fix   (add -Skip RemoteDesktop if you use it)"
        $nla = Get-RegValue -Path "$script:TsPath\WinStations\RDP-Tcp" -Name 'UserAuthentication'
        if ($null -ne $nla -and [int]$nla -eq 1) {
            Add-Finding $findings Remote OK 'Remote Desktop requires Network Level Authentication.'
        } else {
            Add-Finding $findings Remote Risk 'Remote Desktop does not require Network Level Authentication, so anyone who can reach it gets a logon screen.' 'System Properties > Remote > tick "Allow connections only from computers running Remote Desktop with Network Level Authentication"'
        }
    }
    $help = Get-RegValue -Path $script:TsPath -Name 'fAllowToGetHelp'
    if ($null -ne $help -and [int]$help -eq 0) { Add-Finding $findings Remote OK 'Remote Assistance is off.' }
    else { Add-Finding $findings Remote Warn 'Remote Assistance is on.' $fix }

    # --------------------------------------------------------------- services ----
    Write-Section 'Services'
    foreach ($s in @(Get-ServiceInfo -Name 'RemoteRegistry', 'TlntSvr', 'SimpTcp')) {
        if (-not $s.Installed) {
            Add-Finding $findings Services OK "$($s.Name) is not installed."
        } elseif ($s.StartMode -eq 'Disabled' -and $s.State -eq 'Stopped') {
            Add-Finding $findings Services OK "$($s.DisplayName) ($($s.Name)) is stopped and disabled."
        } else {
            Add-Finding $findings Services Warn "$($s.DisplayName) ($($s.Name)) is $($s.State), startup $($s.StartMode)." $fix
        }
    }
    foreach ($s in @(Get-ServiceInfo -Name 'MSMQ', 'upnphost', 'SSDPSRV')) {
        if ($s.Installed -and $s.State -eq 'Running') {
            $note = if ($s.Name -eq 'MSMQ') { 'Remove Message Queuing in Windows Features if no program needs it.' }
                    else { 'Used by network discovery; fine at home, not needed on public Wi-Fi.' }
            Add-Finding $findings Services Info "$($s.DisplayName) ($($s.Name)) is running. $note"
        }
    }

    # ---------------------------------------------------- SMB, NetBIOS, accounts ----
    Write-Section 'SMB, NetBIOS, Guest, AutoRun'
    $smb1 = Get-Smb1State
    if ($null -eq $smb1) { Add-Finding $findings SMB Info 'Could not read whether SMBv1 is on (run as administrator).' }
    elseif ($smb1) { Add-Finding $findings SMB Risk 'The SMBv1 server protocol is ON. WannaCry and NotPetya spread through SMBv1.' $fix }
    else { Add-Finding $findings SMB OK 'The SMBv1 server protocol is off.' }

    $ifaces = @(Get-NetbtInterface)
    $nbOn = @($ifaces | Where-Object { $_.NetbiosOptions -ne 2 })
    if (-not $ifaces.Count) {
        Add-Finding $findings NetBIOS Info 'Could not read the NetBIOS interface settings.'
    } elseif (-not $nbOn.Count) {
        Add-Finding $findings NetBIOS OK "NetBIOS over TCP/IP is off on all $($ifaces.Count) network interface(s)."
    } else {
        # Name the adapters that still exist first; leftovers of removed adapters are only counted.
        $live  = @($nbOn | Where-Object { $_.Description -notlike 'removed adapter*' })
        $gone  = $nbOn.Count - $live.Count
        $parts = @($live | Select-Object -First 4 | ForEach-Object Description)
        if ($live.Count -gt 4) { $parts += "$($live.Count - 4) more" }
        if ($gone) { $parts += "$gone left over from removed adapters" }
        Add-Finding $findings NetBIOS Warn "NetBIOS over TCP/IP is not off on $($nbOn.Count) of $($ifaces.Count) interface(s): $($parts -join ', ')." $fix
    }

    $guest = Get-GuestAccount
    if (-not $guest) { Add-Finding $findings Accounts Info 'Built-in Guest account not found.' }
    elseif (-not $guest.Enabled) { Add-Finding $findings Accounts OK "Guest account (`"$($guest.Name)`") is disabled." }
    else { Add-Finding $findings Accounts Warn "Guest account (`"$($guest.Name)`") is enabled." $fix }

    $autorun = Get-RegValue -Path $script:ExplorerPolicyPath -Name 'NoDriveTypeAutoRun'
    if ($null -ne $autorun -and [int]$autorun -eq 255) {
        Add-Finding $findings AutoRun OK 'AutoRun and AutoPlay are off for all drive types.'
    } else {
        Add-Finding $findings AutoRun Info 'AutoPlay is not turned off for all drive types. Windows no longer runs programs from USB drives by itself, but it still does for CDs and DVDs.' $fix
    }

    # --------------------------------------------------------- logon security ----
    Write-Section 'Logon security'
    $lsaChecks = @(
        @{ Name = 'RestrictAnonymous'; Min = 1; Default = 0
           Good = 'Anonymous listing of accounts and shares is blocked (RestrictAnonymous).'
           Bad  = 'Anonymous (null session) users may list shares (RestrictAnonymous is 0).' }
        @{ Name = 'RestrictAnonymousSAM'; Min = 1; Default = 1
           Good = 'Anonymous listing of accounts is blocked (RestrictAnonymousSAM).'
           Bad  = 'Anonymous (null session) users can list accounts (RestrictAnonymousSAM is 0).' }
        @{ Name = 'NoLMHash'; Min = 1; Default = 1
           Good = 'LM password hashes are not stored (NoLMHash).'
           Bad  = 'Windows stores weak LM password hashes (NoLMHash is 0).' }
        @{ Name = 'LmCompatibilityLevel'; Min = 3; Default = 3
           Good = 'Sends NTLMv2 only (LmCompatibilityLevel 3 or higher).'
           Bad  = 'Still sends weak LM/NTLMv1 logon responses (LmCompatibilityLevel below 3).' }
    )
    foreach ($c in $lsaChecks) {
        # A missing value means the Windows default, which is listed above.
        $v = Get-RegValue -Path $script:LsaPath -Name $c.Name
        $effective = if ($null -eq $v) { $c.Default } else { [int]$v }
        if ($effective -ge $c.Min) { Add-Finding $findings Logon OK $c.Good }
        else { Add-Finding $findings Logon Warn $c.Bad $fix }
    }

    $policy = Get-PasswordPolicy
    if (-not $policy) {
        Add-Finding $findings Logon Info 'Could not read the password policy (net accounts).'
    } else {
        if ($policy.MinLength -ge 8) { Add-Finding $findings Logon OK "Minimum password length is $($policy.MinLength)." }
        else { Add-Finding $findings Logon Warn "Minimum password length is $($policy.MinLength); 8 or more is recommended." $fix }
        if ($policy.LockoutThreshold -gt 0) { Add-Finding $findings Logon OK "Accounts lock after $($policy.LockoutThreshold) bad password tries." }
        else { Add-Finding $findings Logon Warn 'No account lockout: passwords can be guessed without limit.' $fix }
    }

    # ----------------------------------------------------- system protections ----
    Write-Section 'System protections'
    $uac = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA'
    if ($null -ne $uac -and [int]$uac -eq 0) {
        Add-Finding $findings UAC Risk 'User Account Control is off: every program runs with full administrator rights.' 'Control Panel > User Accounts > Change User Account Control settings > move the slider up, then restart'
    } else {
        Add-Finding $findings UAC OK 'User Account Control is on.'
    }

    $os = Get-OsInfo
    if ($os -and $null -ne $os.DataExecutionPrevention_SupportPolicy) {
        # 0 AlwaysOff, 1 AlwaysOn, 2 OptIn (default), 3 OptOut. 64-bit programs always use DEP.
        switch ([int]$os.DataExecutionPrevention_SupportPolicy) {
            0 { Add-Finding $findings DEP Warn 'DEP is turned off (AlwaysOff).' 'bcdedit /set "{current}" nx OptIn   (then restart)' }
            1 { Add-Finding $findings DEP OK 'DEP is on for all programs (AlwaysOn).' }
            2 { Add-Finding $findings DEP OK 'DEP is on (OptIn: Windows and all 64-bit programs).' }
            3 { Add-Finding $findings DEP OK 'DEP is on for all programs except ones you exclude (OptOut).' }
        }
    }

    # ---------------------------------------------------------------- updates ----
    Write-Section 'Windows updates'
    $age = Get-UpdateAgeRating -LastUpdate (Get-LastUpdateDate)
    $updateFix = if ($age.Level -in 'Warn', 'Risk') { 'Settings > Windows Update > Check for updates' } else { '' }
    Add-Finding $findings Updates $age.Level $age.Text $updateFix
    if ($os -and "$($os.Caption)" -match 'Windows 10' -and "$($os.Caption)" -notmatch 'LTS[CB]') {
        Add-Finding $findings Updates Info "$($os.Caption) (build $($os.BuildNumber)): free security updates for Windows 10 ended on October 14, 2025. It only stays patched through Extended Security Updates; moving to a supported Windows version is the lasting fix."
    }

    # -------------------------------------------------------- listening ports ----
    Write-Section 'Listening TCP ports (network-facing)'
    $listeners = @(Get-ListeningTcpPort)
    $ports = @($listeners | ForEach-Object Port | Sort-Object -Unique)
    if (-not $ports.Count) { Add-Finding $findings Ports OK 'Nothing is listening on the network (or the list could not be read).' }
    $other = [System.Collections.Generic.List[int]]::new()
    foreach ($port in $ports) {
        $where = @($listeners | Where-Object Port -eq $port | ForEach-Object Address | Sort-Object -Unique) -join ', '
        if ($port -eq 135) {
            Add-Finding $findings Ports Info "135 RPC on ${where}: always listening on Windows; the firewall decides who can reach it."
        } elseif ($port -in 139, 445) {
            Add-Finding $findings Ports Info "$port $($script:RiskyPorts[$port]) on ${where}: normal while file sharing (the Server service) is on; the firewall decides who can reach it."
        } elseif ($script:RiskyPorts.ContainsKey($port)) {
            $portFix = switch ($port) {
                3389    { "$fix   (RemoteDesktop step)" }
                { $_ -in 5985, 5986 } { 'Disable-PSRemoting -Force; Stop-Service WinRM; Set-Service WinRM -StartupType Disabled' }
                default { 'Find the program: Get-NetTCPConnection -State Listen -LocalPort {0} | ForEach-Object {{ Get-Process -Id $_.OwningProcess }}; turn it off if you do not use it' -f $port }
            }
            Add-Finding $findings Ports Warn "$port $($script:RiskyPorts[$port]) is listening on $where." $portFix
        } elseif ($port -in 7, 9, 13, 17, 19) {
            Add-Finding $findings Ports Warn "$port Simple TCP/IP Services is listening on $where." $fix
        } else {
            $other.Add($port)
        }
    }
    if ($other.Count) {
        $shown = @($other | Select-Object -First 12) -join ', '
        if ($other.Count -gt 12) { $shown += " and $($other.Count - 12) more" }
        Add-Finding $findings Ports Info "$($other.Count) other port(s) are listening: $shown. The firewall blocks them unless a rule allows it. See the programs with: Get-NetTCPConnection -State Listen"
    }

    Write-Section 'Summary'
    Write-FindingSummary -Finding $findings -PointToAssistant

    Save-RunFinding -Name 'Get-HardeningStatus' -Finding $findings
    if ($PassThru) { $findings.ToArray() }
}
