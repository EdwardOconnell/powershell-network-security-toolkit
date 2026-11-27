function Get-AccountAudit {
    <#
    .SYNOPSIS
        Read-only audit of local accounts and logon settings.
    .DESCRIPTION
        Lists the local accounts and who is in Administrators, and flags enabled
        accounts that are allowed a blank password, an enabled built-in Administrator,
        blank-password network logons (LimitBlankPasswordUse), automatic logon and a
        plain-text DefaultPassword in the registry, and a screen that does not lock.
        Changes nothing. The password and lockout policy is checked by Get-HardeningStatus.
    .PARAMETER PassThru
        Also return the accounts and findings as an object.
    .EXAMPLE
        Get-AccountAudit
    #>
    [CmdletBinding()]
    param([switch]$PassThru)

    Assert-Windows
    $findings = [System.Collections.Generic.List[object]]::new()
    Write-Section 'Local accounts'

    $admin = Get-LocalAdminMember
    $adminNames = @(if ($admin) { $admin.Members | ForEach-Object { "$_".ToLower() } })

    $rows = @(foreach ($a in @(Get-LocalAccount)) {
        $rid = ($a.SID -split '-')[-1]
        $builtin = switch ($rid) {
            '500' { 'Administrator' }
            '501' { 'Guest' }
            '503' { 'System managed' }
            '504' { 'System managed' }
            default { '' }
        }
        $lname = $a.Name.ToLower()
        [pscustomobject]@{
            Name = $a.Name; Enabled = $a.Enabled
            Admin = [bool]@($adminNames | Where-Object { $_ -eq $lname -or $_.EndsWith('\' + $lname) }).Count
            PasswordRequired = $a.PasswordRequired; LockedOut = $a.LockedOut; BuiltIn = $builtin
        }
    }) | Sort-Object Name
    $rows = @($rows)
    if (-not $rows.Count) {
        Add-Finding $findings Accounts Info 'Could not read the local accounts (Win32_UserAccount).'
    } else {
        $rows | Show-Table
    }

    foreach ($r in $rows) {
        if (-not $r.Enabled) { continue }
        # Guest never requires a password; Get-HardeningStatus covers it.
        if (-not $r.PasswordRequired -and $r.BuiltIn -ne 'Guest') {
            Add-Finding $findings Accounts Warn "`"$($r.Name)`" is allowed to have a blank password (PasswordRequired = False). It may still have one; this only closes the option." "net user `"$($r.Name)`" /passwordreq:yes"
        }
        if ($r.BuiltIn -eq 'Administrator') {
            Add-Finding $findings Accounts Warn "The built-in Administrator account (`"$($r.Name)`") is enabled. It is the first account attackers try." "Use your own administrator account, then: net user `"$($r.Name)`" /active:no"
        }
        if ($r.LockedOut) {
            Add-Finding $findings Accounts Info "`"$($r.Name)`" is locked out after bad password tries."
        }
    }

    if (-not $admin) {
        Add-Finding $findings Accounts Info 'Could not read the Administrators group (net localgroup).'
    } elseif ($rows.Count) {
        $enabledAdmins = @($rows | Where-Object { $_.Enabled -and $_.Admin } | ForEach-Object Name)
        $level = if ($enabledAdmins.Count -gt 2) { 'Warn' } else { 'Info' }
        Add-Finding $findings Accounts $level "$($enabledAdmins.Count) enabled local administrator account(s): $($enabledAdmins -join ', '). Use a standard account for everyday work."
    }

    Write-Section 'Logon settings'
    $blank = Get-RegValue -Path $script:LsaPath -Name 'LimitBlankPasswordUse'
    if ($null -ne $blank -and [int]$blank -eq 0) {
        Add-Finding $findings Logon Risk 'Accounts with blank passwords can log on over the network (LimitBlankPasswordUse = 0).' 'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f'
    } else {
        Add-Finding $findings Logon OK 'Blank-password accounts can only log on at the keyboard (LimitBlankPasswordUse = 1).'
    }

    $auto  = "$(Get-RegValue -Path $script:WinlogonPath -Name 'AutoAdminLogon')" -eq '1'
    $plain = [bool]"$(Get-RegValue -Path $script:WinlogonPath -Name 'DefaultPassword')"
    $who   = "$(Get-RegValue -Path $script:WinlogonPath -Name 'DefaultUserName')"
    $delPw = 'reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /f'
    if ($auto -and $plain) {
        Add-Finding $findings Logon Risk "Automatic logon is on and the password for `"$who`" is stored in plain text in the registry (Winlogon DefaultPassword)." "$delPw; then run netplwiz and tick `"Users must enter a user name and password`""
    } elseif ($auto) {
        Add-Finding $findings Logon Warn "Automatic logon is on: anyone who turns this PC on gets the desktop of `"$who`"." 'Run netplwiz and tick "Users must enter a user name and password to use this computer"'
    } elseif ($plain) {
        Add-Finding $findings Logon Warn 'Automatic logon is off, but a plain-text DefaultPassword is still in the registry.' $delPw
    } else {
        Add-Finding $findings Logon OK 'Automatic logon is off.'
    }

    $desk = 'HKCU:\Control Panel\Desktop'
    $saverOn     = "$(Get-RegValue -Path $desk -Name 'ScreenSaveActive')" -eq '1'
    $saverSecure = "$(Get-RegValue -Path $desk -Name 'ScreenSaverIsSecure')" -eq '1'
    if ($saverOn -and $saverSecure) {
        $secs = 0
        [void][int]::TryParse("$(Get-RegValue -Path $desk -Name 'ScreenSaveTimeOut')", [ref]$secs)
        Add-Finding $findings Logon OK "The screen saver locks the PC after $([int]($secs / 60)) minute(s) (this user)."
    } else {
        Add-Finding $findings Logon Info 'No screen saver lock for this user. The PC may still lock when it sleeps; check that it asks for sign-in.' 'Settings > Accounts > Sign-in options > "If you''ve been away, when should Windows require you to sign in again?"; Windows key + L locks right away'
    }

    Save-RunFinding -Name 'Get-AccountAudit' -Finding $findings
    if ($PassThru) {
        [pscustomobject]@{ Accounts = $rows; Administrators = $adminNames; Findings = $findings.ToArray() }
    }
}
