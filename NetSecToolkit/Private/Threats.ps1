# Threat ratings for Get-ThreatExposure. Pure logic: it only reads the state
# object it is given, so every branch can be unit tested.

function Get-ThreatRatingList {
    # State properties: FirewallOn, Smb1 ($true/$false/$null), ServerRunning,
    # SmbRuleOpen, RdpOn, RdpNla, RdpRuleOpen, AutoRunOff, GuestOff, Lockout,
    # AnonBlocked, NoLm, Ntlm2, LsaProtection, UacOn, Antivirus (objects with
    # Name, RealTime, UpToDate), UpdateDays (days since the last update, or $null).
    param([Parameter(Mandatory)]$State)
    $s = $State
    $fix = $script:HardeningFix
    $updateFix = 'Settings > Windows Update > Check for updates'

    # 1. SMB worms
    $name = 'SMB worms (WannaCry, EternalBlue)'
    $smbReachable = $s.ServerRunning -and (-not $s.FirewallOn -or $s.SmbRuleOpen)
    if ($null -eq $s.Smb1) {
        New-ThreatRating $name Unknown 'Could not read whether SMBv1 is on' 'Run Get-ThreatExposure in an Administrator window' $false
    } elseif (-not $s.Smb1) {
        if ($null -ne $s.UpdateDays -and $s.UpdateDays -gt 120) {
            New-ThreatRating $name Partly "SMBv1 is off, but Windows has not been updated in $($s.UpdateDays) days, so newer file-sharing flaws are unpatched" $updateFix $false
        } else {
            New-ThreatRating $name Protected 'SMBv1, the protocol these worms use, is off' '' $false
        }
    } elseif (-not $smbReachable) {
        New-ThreatRating $name Partly 'SMBv1 is ON, but the firewall or settings block file sharing right now' "$fix (SMBv1 step)" $false
    } else {
        New-ThreatRating $name Exposed 'SMBv1 is ON and file sharing is reachable: one infected device on this network can attack this PC' "$fix (SMBv1 step)" $false
    }

    # 2. Remote Desktop
    $name = 'Remote Desktop attacks (BlueKeep, password guessing)'
    $rdpReachable = $s.RdpOn -and (-not $s.FirewallOn -or $s.RdpRuleOpen)
    if (-not $s.RdpOn) {
        New-ThreatRating $name Protected 'Remote Desktop is turned off' '' $false
    } elseif (-not $rdpReachable) {
        New-ThreatRating $name Protected 'Remote Desktop is on, but the firewall blocks it' '' $false
    } else {
        $gaps = @(
            if (-not $s.RdpNla) { 'no Network Level Authentication' }
            if (-not $s.Lockout) { 'no account lockout' }
        )
        if ($gaps.Count) {
            New-ThreatRating $name Exposed "Remote Desktop is open to the network with $($gaps -join ' and ')" "$fix (or turn on NLA and keep the PasswordPolicy step)" $false
        } else {
            New-ThreatRating $name Partly 'Remote Desktop is open to the network; NLA and account lockout are on' "$fix, or keep it and never forward port 3389 on the router" $false
        }
    }

    # 3. USB worms
    $name = 'USB worms (AutoRun)'
    if ($s.AutoRunOff) {
        New-ThreatRating $name Protected 'AutoRun and AutoPlay are off for all drive types' '' $false
    } else {
        New-ThreatRating $name Partly 'Windows no longer runs programs from USB drives by itself, but AutoPlay is still on for discs and offers actions for drives' "$fix (AutoRun step)" $true
    }

    # 4. Password guessing
    $name = 'Password guessing (botnets)'
    $gaps = @(
        if (-not $s.FirewallOn) { 'firewall off' }
        if (-not $s.GuestOff) { 'Guest enabled' }
        if (-not $s.Lockout) { 'no account lockout' }
        if (-not $s.AnonBlocked) { 'anonymous listing allowed' }
    )
    if (-not $gaps.Count) {
        New-ThreatRating $name Protected 'Firewall on, Guest off, lockout on, anonymous listing blocked' '' $false
    } elseif (-not $s.FirewallOn -or -not $s.GuestOff) {
        New-ThreatRating $name Exposed ($gaps -join '; ') $fix $false
    } else {
        New-ThreatRating $name Partly ($gaps -join '; ') $fix $false
    }

    # 5. Password theft
    $name = 'Password theft (stored hashes)'
    if (-not $s.NoLm -or -not $s.Ntlm2) {
        $why = @(
            if (-not $s.NoLm) { 'LM hashes stored (crackable in seconds)' }
            if (-not $s.Ntlm2) { 'sends weak NTLMv1/LM logons' }
        )
        New-ThreatRating $name Exposed ($why -join '; ') "$fix (NoLMHash, NTLMv2), then change passwords" $false
    } elseif ($s.LsaProtection) {
        New-ThreatRating $name Protected 'No LM hashes, NTLMv2 only, and LSA protection is on' '' $false
    } else {
        New-ThreatRating $name Partly 'No LM hashes and NTLMv2 only; LSA protection is off, so malware running as administrator could still read logon secrets' 'Windows Security > Device security > Core isolation > Local Security Authority protection; use a standard account day to day' $true
    }

    # 6. Ransomware and malware
    $name = 'Ransomware and malware (web, email, downloads)'
    $av     = @($s.Antivirus | Where-Object { $_ })
    $active = @($av | Where-Object RealTime)
    if (-not $active.Count) {
        $why = if ($av.Count) { "real-time protection is off ($(@($av | ForEach-Object Name) -join ', '))" } else { 'no antivirus with real-time protection was found' }
        New-ThreatRating $name Exposed $why 'Windows Security > Virus & threat protection > Manage settings > Real-time protection' $false
    } else {
        $names = @($active | ForEach-Object Name) -join ', '
        $gaps = @(
            if (-not @($active | Where-Object UpToDate).Count) { 'virus definitions are out of date' }
            if (-not $s.UacOn) { 'UAC is off' }
        )
        if ($gaps.Count) {
            New-ThreatRating $name Partly "$names is on, but $($gaps -join ' and ')" 'Update the antivirus definitions; turn UAC back on' $false
        } else {
            New-ThreatRating $name Protected "$names is on with current definitions, and UAC is on. Still think before opening attachments" '' $false
        }
    }

    # 7. Unpatched flaws
    $name = 'Unpatched Windows flaws'
    if ($null -eq $s.UpdateDays) {
        New-ThreatRating $name Unknown 'Could not read when Windows was last updated' $updateFix $false
    } elseif ($s.UpdateDays -le 45) {
        New-ThreatRating $name Protected "Windows was updated $($s.UpdateDays) day(s) ago" '' $false
    } elseif ($s.UpdateDays -le 120) {
        New-ThreatRating $name Partly "The last Windows update was $($s.UpdateDays) days ago" $updateFix $false
    } else {
        New-ThreatRating $name Exposed "No Windows update in $($s.UpdateDays) days: publicly known flaws are unpatched" $updateFix $false
    }
}
