function Set-FirewallBaseline {
    <#
    .SYNOPSIS
        Applies the Windows Firewall fixes that Get-FirewallAudit recommends.
    .DESCRIPTION
        Turns on logging of blocked connections for every firewall profile (with a larger
        log size), and disables the Remote Assistance firewall rules. Only settings that
        aren't already compliant are changed.

        This is the only NetSecToolkit command that changes settings. It supports -WhatIf
        to preview the changes and -Confirm to approve each one.
        If Group Policy manages the firewall, those policies override local changes.
    .PARAMETER LogMaxSizeKilobytes
        Size limit for the firewall log. Default: 16384 KB (16 MB).
    .PARAMETER SkipLogging
        Don't change logging settings.
    .PARAMETER SkipRemoteAssistance
        Don't disable the Remote Assistance rules.
    .PARAMETER PassThru
        Also return the list of changes made.
    .EXAMPLE
        Set-FirewallBaseline -WhatIf
        Shows what would change without changing anything.
    .EXAMPLE
        Set-FirewallBaseline
        Applies the fixes, then run Get-FirewallAudit to confirm.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [ValidateRange(4096, 32767)][int]$LogMaxSizeKilobytes = 16384,
        [switch]$SkipLogging,
        [switch]$SkipRemoteAssistance,
        [switch]$PassThru
    )

    Assert-Administrator
    $changes = [System.Collections.Generic.List[string]]::new()

    Write-Section 'Firewall logging'
    if ($SkipLogging) {
        Write-Host '  Skipped.'
    } else {
        foreach ($p in Get-NetFirewallProfile) {
            $needsLogging = "$($p.LogBlocked)" -ne 'True'
            $needsSize    = $p.LogMaxSizeKilobytes -lt $LogMaxSizeKilobytes
            if (-not ($needsLogging -or $needsSize)) {
                Write-Host "  $($p.Name): already logging blocked connections." -ForegroundColor Green
                continue
            }
            if ($PSCmdlet.ShouldProcess("$($p.Name) firewall profile",
                    "Log blocked connections, log size $LogMaxSizeKilobytes KB")) {
                Set-NetFirewallProfile -Name $p.Name -LogBlocked True -LogMaxSizeKilobytes $LogMaxSizeKilobytes
                $changes.Add("$($p.Name) profile: logging of blocked connections enabled ($LogMaxSizeKilobytes KB).")
                Write-Host "  $($p.Name): logging enabled." -ForegroundColor Yellow
            }
        }
    }

    Write-Section 'Remote Assistance rules'
    if ($SkipRemoteAssistance) {
        Write-Host '  Skipped.'
    } else {
        $rules = @(Get-NetFirewallRule -DisplayGroup 'Remote Assistance' -ErrorAction SilentlyContinue |
                   Where-Object { "$($_.Enabled)" -eq 'True' })
        if (-not $rules.Count) {
            Write-Host '  Already disabled.' -ForegroundColor Green
        } elseif ($PSCmdlet.ShouldProcess("$($rules.Count) Remote Assistance firewall rule(s)", 'Disable')) {
            $rules | Disable-NetFirewallRule
            $changes.Add("Disabled $($rules.Count) Remote Assistance firewall rule(s).")
            Write-Host "  Disabled $($rules.Count) rule(s)." -ForegroundColor Yellow
        }
    }

    Write-Section 'Summary'
    if ($changes.Count) {
        $changes | ForEach-Object { Write-Host "[+] $_" -ForegroundColor Yellow }
        Write-Host "`nRun Get-FirewallAudit to confirm." -ForegroundColor Green
    } elseif ($WhatIfPreference) {
        Write-Host 'Preview only (-WhatIf). Nothing was changed.' -ForegroundColor Cyan
    } else {
        Write-Host 'Already compliant. Nothing to change.' -ForegroundColor Green
    }

    if ($PassThru) { $changes.ToArray() }
}
