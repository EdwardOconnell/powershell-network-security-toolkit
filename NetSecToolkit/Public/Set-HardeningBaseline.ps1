function Set-HardeningBaseline {
    <#
    .SYNOPSIS
        Applies the hardening baseline that Get-HardeningStatus checks, in one run.
    .DESCRIPTION
        Turns the firewall on for every profile with inbound connections blocked by
        default and blocked connections logged, turns off Remote Assistance and Remote
        Desktop, disables Remote Registry, Telnet and Simple TCP/IP Services, turns off
        the SMBv1 server protocol and NetBIOS over TCP/IP, disables the Guest account,
        blocks anonymous (null session) listing, stops storing LM password hashes,
        sends NTLMv2 only, sets a password policy (8+ characters, lockout after 10 bad
        tries) and turns off AutoRun.

        Each step reports Applied, N/A (not installed), Skipped or Failed. Run it with
        -WhatIf first to see what it will do; -Confirm asks before each step.
        File sharing itself is left alone. If Group Policy manages a setting, the
        policy overrides the local change.
    .PARAMETER Skip
        Step names to leave alone, e.g. -Skip RemoteDesktop to keep Remote Desktop
        working, or -Skip NetBIOS if you reach an old NAS or printer by its name.
    .PARAMETER PassThru
        Also return the step results as objects.
    .EXAMPLE
        Set-HardeningBaseline -WhatIf
        Shows every step without changing anything.
    .EXAMPLE
        Set-HardeningBaseline
        Applies every step, then run Get-HardeningStatus to confirm.
    .EXAMPLE
        Set-HardeningBaseline -Skip RemoteDesktop, NetBIOS
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [ValidateSet('Firewall', 'Logging', 'RemoteAssistance', 'RemoteDesktop', 'RemoteRegistry', 'LegacyServices',
                     'SMBv1', 'NetBIOS', 'Guest', 'RestrictAnonymous', 'NoLMHash', 'NTLMv2', 'PasswordPolicy', 'AutoRun')]
        [string[]]$Skip = @(),
        [switch]$PassThru
    )

    # -WhatIf works without elevation, so the preview can be read anywhere.
    if ($WhatIfPreference) { Assert-Windows } else { Assert-Administrator }

    $disableService = {
        param([string[]]$Names)
        $done = foreach ($n in $Names) {
            $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
            if (-not $svc) { "${n}: not installed"; continue }
            if ($svc.Status -ne 'Stopped') { Stop-Service -Name $n -Force -ErrorAction Stop }
            Set-Service -Name $n -StartupType Disabled -ErrorAction Stop
            "${n}: stopped and disabled"
        }
        $done -join '; '
    }
    $disableRuleGroup = {
        param([string]$Group)
        $rules = @(Get-NetFirewallRule -DisplayGroup $Group -ErrorAction SilentlyContinue | Where-Object { "$($_.Enabled)" -eq 'True' })
        if ($rules.Count) { $rules | Disable-NetFirewallRule -ErrorAction Stop }
        $rules.Count
    }

    $steps = @(
        @{ Name = 'Firewall'; Reboot = $false
           Action = 'Turn the firewall on for the Domain, Private and Public profiles and block inbound connections by default'
           Run = { Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -ErrorAction Stop; 'On for all profiles, inbound blocked by default' } }
        @{ Name = 'Logging'; Reboot = $false
           Action = 'Log blocked connections to pfirewall.log on every profile (16 MB log)'
           Run = {
               foreach ($p in Get-NetFirewallProfile) {
                   $size = [math]::Max([int]$p.LogMaxSizeKilobytes, 16384)
                   Set-NetFirewallProfile -Name $p.Name -LogBlocked True -LogMaxSizeKilobytes $size -ErrorAction Stop
               }
               'Blocked connections are logged'
           } }
        @{ Name = 'RemoteAssistance'; Reboot = $false
           Action = 'Turn off Remote Assistance (fAllowToGetHelp = 0) and its firewall rules'
           Run = {
               Set-RegDword -Path $script:TsPath -Name 'fAllowToGetHelp' -Value 0
               'Remote Assistance off, {0} firewall rule(s) disabled' -f (& $disableRuleGroup 'Remote Assistance')
           } }
        @{ Name = 'RemoteDesktop'; Reboot = $false
           Action = 'Turn off Remote Desktop (fDenyTSConnections = 1) and its firewall rules'
           Run = {
               Set-RegDword -Path $script:TsPath -Name 'fDenyTSConnections' -Value 1
               'Remote Desktop off, {0} firewall rule(s) disabled' -f (& $disableRuleGroup 'Remote Desktop')
           } }
        @{ Name = 'RemoteRegistry'; Reboot = $false
           Action = 'Stop and disable Remote Registry'
           Run = { & $disableService 'RemoteRegistry' } }
        @{ Name = 'LegacyServices'; Reboot = $false
           Action = 'Stop and disable the Telnet server and Simple TCP/IP Services, if installed'
           Run = { & $disableService 'TlntSvr', 'SimpTcp' } }
        @{ Name = 'SMBv1'; Reboot = $false
           Action = 'Turn off the SMBv1 server protocol (SMBv2 and SMBv3 file sharing keep working)'
           Run = { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false -ErrorAction Stop; 'SMBv1 server off' } }
        @{ Name = 'NetBIOS'; Reboot = $false
           Action = 'Turn off NetBIOS over TCP/IP on every network interface, including disabled ones (ports 137-139)'
           Run = {
               # 1. Registry: every interface, so adapters that are disabled or
               #    unplugged right now stay off when they come back.
               $ifaces = @(Get-NetbtInterface)
               foreach ($i in $ifaces) { Set-RegDword -Path $i.Path -Name 'NetbiosOptions' -Value 2 }
               # 2. CIM: IP-enabled adapters, so the change applies right away.
               #    ReturnValue 0 = done, 1 = done but needs a restart.
               $bad = @(); $live = 0; $restart = $false
               foreach ($c in @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = TRUE' -ErrorAction Stop)) {
                   $r = Invoke-CimMethod -InputObject $c -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } -ErrorAction Stop
                   if ($r.ReturnValue -eq 0) { $live++ }
                   elseif ($r.ReturnValue -eq 1) { $live++; $restart = $true }
                   else { $bad += '{0} (code {1})' -f $c.Description, $r.ReturnValue }
               }
               if ($bad.Count) { throw ('Failed on: ' + ($bad -join '; ')) }
               $msg = '{0} interface(s) set, {1} active adapter(s) applied now' -f $ifaces.Count, $live
               if ($restart) { $msg += ' (restart required)' }
               $msg
           } }
        @{ Name = 'Guest'; Reboot = $false
           Action = 'Disable the built-in Guest account (found by SID, so a renamed Guest is covered)'
           Run = {
               $g = Get-GuestAccount
               if (-not $g) { return 'Guest: not installed' }
               $out = & net.exe user $g.Name /active:no 2>&1
               if ($LASTEXITCODE -ne 0) { throw (($out | Out-String).Trim()) }
               'Guest account "{0}" disabled' -f $g.Name
           } }
        @{ Name = 'RestrictAnonymous'; Reboot = $true
           Action = 'Block anonymous (null session) listing of accounts and shares (RestrictAnonymous = 1, RestrictAnonymousSAM = 1)'
           Run = {
               Set-RegDword -Path $script:LsaPath -Name 'RestrictAnonymous' -Value 1
               Set-RegDword -Path $script:LsaPath -Name 'RestrictAnonymousSAM' -Value 1
               'Set, restart to apply'
           } }
        @{ Name = 'NoLMHash'; Reboot = $false
           Action = 'Stop storing weak LM password hashes (NoLMHash = 1)'
           Run = { Set-RegDword -Path $script:LsaPath -Name 'NoLMHash' -Value 1; 'Set' } }
        @{ Name = 'NTLMv2'; Reboot = $false
           Action = 'Send NTLMv2 responses only (LmCompatibilityLevel at least 3)'
           Run = {
               $v = Get-RegValue -Path $script:LsaPath -Name 'LmCompatibilityLevel'
               if ($null -ne $v -and [int]$v -ge 3) { return "Already $v, left alone" }
               Set-RegDword -Path $script:LsaPath -Name 'LmCompatibilityLevel' -Value 3
               'Set to 3'
           } }
        @{ Name = 'PasswordPolicy'; Reboot = $false
           Action = 'Password policy: 8+ characters, lock out for 30 minutes after 10 bad tries (net accounts)'
           Run = {
               $policy = Get-PasswordPolicy
               # Never weaken a stricter policy that is already set.
               if (-not $policy -or $policy.MinLength -lt 8) {
                   $out = & net.exe accounts /minpwlen:8 2>&1
                   if ($LASTEXITCODE -ne 0) { throw (($out | Out-String).Trim()) }
               }
               if (-not $policy -or $policy.LockoutThreshold -eq 0 -or $policy.LockoutThreshold -gt 10) {
                   $out = & net.exe accounts /lockoutthreshold:10 /lockoutwindow:30 /lockoutduration:30 2>&1
                   if ($LASTEXITCODE -ne 0) { throw ('Minimum length set, lockout not set: ' + ($out | Out-String).Trim()) }
               }
               'Min length 8 or more, lockout after 10 tries or fewer (a new length applies at the next password change)'
           } }
        @{ Name = 'AutoRun'; Reboot = $false
           Action = 'Turn off AutoRun and AutoPlay on all drive types (NoDriveTypeAutoRun = 0xFF)'
           Run = { Set-RegDword -Path $script:ExplorerPolicyPath -Name 'NoDriveTypeAutoRun' -Value 255; 'Set to 0xFF' } }
    )

    Write-Section 'Set-HardeningBaseline'
    $colors = @{ Applied = 'Green'; 'N/A' = 'Gray'; Skipped = 'Gray'; Failed = 'Red'; WhatIf = 'Cyan'; Declined = 'Yellow' }
    $results = [System.Collections.Generic.List[object]]::new()
    $needReboot = $false
    foreach ($s in $steps) {
        if ($s.Name -in $Skip) {
            $status = 'Skipped'; $detail = 'Left alone (-Skip)'
        } elseif ($PSCmdlet.ShouldProcess($s.Name, $s.Action)) {
            try {
                # The step was approved above; do not ask again for each cmdlet inside it.
                $detail = "$(& { $ConfirmPreference = 'None'; & $s.Run })"
                $status = if ($detail -match 'not installed' -and $detail -notmatch 'disabled') { 'N/A' } else { 'Applied' }
                if ($s.Reboot) { $needReboot = $true }
                if ($detail -match 'restart required') { $needReboot = $true }
            } catch {
                $status = 'Failed'; $detail = $_.Exception.Message
            }
        } else {
            $status = if ($WhatIfPreference) { 'WhatIf' } else { 'Declined' }
            $detail = $s.Action
        }
        # With -WhatIf, PowerShell has already printed the "What if:" line for this step.
        if ($status -ne 'WhatIf') {
            Write-Host ('  [{0,-8}] {1,-17} {2}' -f $status, $s.Name, $detail) -ForegroundColor $colors[$status]
        }
        $results.Add([pscustomobject]@{ Step = $s.Name; Status = $status; Detail = $detail })
    }

    $failed = @($results | Where-Object Status -eq 'Failed')
    Write-Host ''
    if ($failed.Count) {
        Write-Host "  $($failed.Count) step(s) failed. Fix the cause or re-run with -Skip for those steps." -ForegroundColor Yellow
    }
    if ($WhatIfPreference) {
        Write-Host '  Preview only (-WhatIf). Nothing was changed.' -ForegroundColor Cyan
    } elseif ($needReboot) {
        Write-Host '  Restart the PC so every change applies, then run Get-HardeningStatus to confirm.' -ForegroundColor Yellow
    } elseif (@($results | Where-Object Status -eq 'Applied').Count) {
        Write-Host '  Run Get-HardeningStatus to confirm.' -ForegroundColor Green
    }

    if ($PassThru) { $results.ToArray() }
}
