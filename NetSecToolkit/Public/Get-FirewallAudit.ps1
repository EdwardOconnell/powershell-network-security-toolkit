function Get-FirewallAudit {
    <#
    .SYNOPSIS
        Audits Windows Defender Firewall: service, profiles, logging, network categories,
        risky inbound rules, and programs allowed from user-writable folders.
    .DESCRIPTION
        Reads the ActiveStore, the effective policy including Group Policy. Read-only.
    .PARAMETER ExportPath
        Save every enabled inbound allow rule to this CSV file.
    .PARAMETER PassThru
        Also return the results (rules and warnings) as an object.
    .EXAMPLE
        Get-FirewallAudit
    .EXAMPLE
        Get-FirewallAudit -ExportPath C:\fw-rules.csv
    #>
    [CmdletBinding()]
    param(
        [string]$ExportPath,
        [switch]$PassThru
    )

    Assert-Administrator
    $warnings = [System.Collections.Generic.List[string]]::new()

    Write-Section 'Firewall service'
    $svc = Get-Service -Name mpssvc
    $svc | Select-Object Name, DisplayName, Status, StartType | Show-Table
    if ($svc.Status -ne 'Running') { $warnings.Add("Firewall service (mpssvc) is $($svc.Status).") }

    Write-Section 'Profiles (effective)'
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    $profiles |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction,
                      LogBlocked, LogAllowed, LogMaxSizeKilobytes |
        Show-Table
    foreach ($p in $profiles) {
        if ("$($p.Enabled)" -ne 'True')              { $warnings.Add("$($p.Name) profile is DISABLED.") }
        if ("$($p.DefaultInboundAction)" -eq 'Allow') { $warnings.Add("$($p.Name) profile ALLOWS inbound traffic by default.") }
        if ("$($p.LogBlocked)" -ne 'True')           { $warnings.Add("$($p.Name) profile is not logging blocked connections.") }
    }

    Write-Section 'Active networks'
    Get-NetConnectionProfile |
        Select-Object InterfaceAlias, Name, NetworkCategory, IPv4Connectivity |
        Show-Table

    Write-Section 'Inbound allow rules'
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow)

    # Pull every filter once and index it (much faster than per-rule lookups)
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
            Source     = "$($r.PolicyStoreSourceType)"
            Risky      = @(Get-RiskyPortMatch -Ports $pf.LocalPort) -join ', '
        }
    })
    $openToAny = @($ruleInfo | Where-Object RemoteAddr -eq 'Any').Count
    Write-Host ('  {0} enabled inbound allow rules ({1} open to any remote address).' -f $ruleInfo.Count, $openToAny)

    Write-Host "`n  Rules exposing commonly attacked ports:" -ForegroundColor Yellow
    $risky = @($ruleInfo | Where-Object Risky)
    $risky | Select-Object Name, Profile, Protocol, LocalPort, RemoteAddr, Risky | Show-Table -Wrap
    foreach ($r in ($risky | Where-Object RemoteAddr -eq 'Any')) {
        $warnings.Add("'$($r.Name)' opens $($r.Risky) to ANY remote address ($($r.Profile) profile).")
    }

    Write-Host '  Allowed programs in user-writable folders:' -ForegroundColor Yellow
    $userPath = '\\Users\\|\\Temp\\|%(APPDATA|LOCALAPPDATA|TEMP|TMP|USERPROFILE)%'
    $suspect  = @($ruleInfo | Where-Object { $_.Program -match $userPath })
    $suspect | Select-Object Name, Profile, Program | Show-Table -Wrap
    if ($suspect.Count) {
        $warnings.Add("$($suspect.Count) inbound rule(s) allow programs in user folders. Review the list above.")
    }

    if ($ExportPath) {
        $ruleInfo | Export-Csv -Path $ExportPath -NoTypeInformation
        Write-Host "  Full rule list exported to $ExportPath"
    }

    Write-Section 'Summary'
    if ($warnings.Count) { $warnings | ForEach-Object { Write-Host "[!] $_" -ForegroundColor Red } }
    else                 { Write-Host 'No issues found.' -ForegroundColor Green }

    if ($PassThru) {
        [pscustomobject]@{ Profiles = $profiles; InboundRules = $ruleInfo; Warnings = $warnings.ToArray() }
    }
}
