function Get-ThreatExposure {
    <#
    .SYNOPSIS
        Rates this PC against the threats that most often hit Windows PCs.
    .DESCRIPTION
        For each threat (SMB worms such as WannaCry, Remote Desktop attacks, USB worms,
        password guessing, password theft, ransomware and malware, and unpatched
        Windows flaws) it reads the settings that decide whether it could work here,
        and rates it Protected, Partly or Exposed, with the reason and the fix.
        Exposed threats that a setting can fix are Risks. Ratings come from this PC's
        settings and update history, not from scanning files. Changes nothing.
    .PARAMETER PassThru
        Also return the ratings and findings as an object.
    .EXAMPLE
        Get-ThreatExposure
    #>
    [CmdletBinding()]
    param([switch]$PassThru)

    Assert-Windows
    Write-Section 'What this PC is exposed to'

    $fw      = Get-FirewallState
    $policy  = Get-PasswordPolicy
    $guest   = Get-GuestAccount
    $server  = Get-ServiceInfo -Name 'LanmanServer' | Select-Object -First 1
    $age     = Get-UpdateAgeRating -LastUpdate (Get-LastUpdateDate)
    $lsa     = { param($n, $default) $v = Get-RegValue -Path $script:LsaPath -Name $n; if ($null -eq $v) { $default } else { [int]$v } }
    $deny    = Get-RegValue -Path $script:TsPath -Name 'fDenyTSConnections'
    $nla     = Get-RegValue -Path "$script:TsPath\WinStations\RDP-Tcp" -Name 'UserAuthentication'
    $autorun = Get-RegValue -Path $script:ExplorerPolicyPath -Name 'NoDriveTypeAutoRun'
    $uac     = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA'

    $state = [pscustomobject]@{
        FirewallOn    = [bool]$fw.AllOn -and -not $fw.AnyInboundAllow
        Smb1          = Get-Smb1State
        ServerRunning = ($server -and $server.State -eq 'Running')
        SmbRuleOpen   = [bool]$fw.SmbRuleOpen
        RdpOn         = ($null -ne $deny -and [int]$deny -eq 0)
        RdpNla        = ($null -ne $nla -and [int]$nla -eq 1)
        RdpRuleOpen   = [bool]$fw.RdpRuleOpen
        AutoRunOff    = ($null -ne $autorun -and [int]$autorun -eq 255)
        GuestOff      = (-not $guest -or -not $guest.Enabled)
        Lockout       = [bool]($policy -and $policy.LockoutThreshold -gt 0)
        AnonBlocked   = (& $lsa 'RestrictAnonymous' 0) -ge 1
        NoLm          = (& $lsa 'NoLMHash' 1) -ge 1
        Ntlm2         = (& $lsa 'LmCompatibilityLevel' 3) -ge 3
        LsaProtection = (& $lsa 'RunAsPPL' 0) -in 1, 2
        UacOn         = -not ($null -ne $uac -and [int]$uac -eq 0)
        Antivirus     = @(Get-AntivirusStatus)
        UpdateDays    = $age.Days
    }
    if ($fw.Error) {
        Write-Finding -Level Info -Message "Could not read the firewall policy ($($fw.Error)); the ratings below treat the firewall as off. Run as administrator."
    }

    $ratings = @(Get-ThreatRatingList -State $state)
    $ratings | Select-Object Threat, Rating, Why | Show-Table -Wrap

    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $ratings) {
        $level = ConvertTo-ThreatLevel -Rating $r.Rating -Inherent $r.Inherent
        Add-Finding $findings Threats $level ('{0}: {1}. {2}.' -f $r.Threat, $r.Rating.ToUpper(), $r.Why) $r.Fix
    }
    $exposed   = @($ratings | Where-Object Rating -eq 'Exposed').Count
    $protected = @($ratings | Where-Object Rating -eq 'Protected').Count
    Write-Host "`n  $protected of $($ratings.Count) threats blocked, $exposed exposed. Ratings come from this PC's settings, not from scanning files." -ForegroundColor DarkGray

    Save-RunFinding -Name 'Get-ThreatExposure' -Finding $findings
    if ($PassThru) { [pscustomobject]@{ Ratings = $ratings; Findings = $findings.ToArray() } }
}
