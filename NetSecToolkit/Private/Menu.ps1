# Helpers for Start-NetSecToolkit. Not exported.

function Show-ToolkitMenu {
    $admin = if (Test-IsAdministrator) { 'yes' } else { 'NO (most checks and option H need an Administrator window)' }
    Write-Host ''
    Write-Host ('=' * 64) -ForegroundColor DarkCyan
    Write-Host " NetSecToolkit $script:ToolkitVersion - Windows security toolkit" -ForegroundColor Cyan
    Write-Host " $script:Copyright" -ForegroundColor DarkGray
    Write-Host " Computer: $env:COMPUTERNAME   User: $env:USERNAME   Administrator: $admin" -ForegroundColor DarkGray
    Write-Host ('=' * 64) -ForegroundColor DarkCyan
    Write-Host '  Checks (change nothing)' -ForegroundColor White
    Write-Host '    1  Full security check (all of the below, saves a report)'
    Write-Host '    2  Hardening status'
    Write-Host '    3  Firewall rules'
    Write-Host '    4  Accounts and logon'
    Write-Host '    5  Firewall log (what was blocked)'
    Write-Host '    6  Devices on the network'
    Write-Host '    7  Router ports'
    Write-Host '    8  Network adapters and connectivity'
    Write-Host '    9  USB storage history'
    Write-Host '    V  Virus and threat check (what this PC is exposed to, signs of malware)'
    Write-Host '    S  Speed test'
    Write-Host '  Fix' -ForegroundColor White
    Write-Host '    H  Harden this PC (shows a preview first)'
    Write-Host '  Help' -ForegroundColor White
    Write-Host '    A  Ask the assistant (what to fix first, what a finding means)'
    Write-Host '    R  Open the last report'
    Write-Host '    P  PowerShell prompt with the toolkit loaded (type exit to come back)'
    Write-Host '    Q  Quit'
}

function Get-HardeningStepName {
    # The step names Set-HardeningBaseline -Skip accepts.
    (Get-Command Set-HardeningBaseline).Parameters['Skip'].Attributes |
        Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
        ForEach-Object { $_.ValidValues }
}

function ConvertTo-SkipList {
    # Splits what the user typed ("RemoteDesktop, netbios") into valid step
    # names (in their proper case) and the entries that are not step names.
    param([string]$Text, [string[]]$Valid)
    $skip = [System.Collections.Generic.List[string]]::new()
    $unknown = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in @("$Text" -split '[,\s]+' | Where-Object { $_ })) {
        $match = $Valid | Where-Object { $_ -eq $entry } | Select-Object -First 1
        if ($match) { if ($match -notin $skip) { $skip.Add($match) } } else { $unknown.Add($entry) }
    }
    [pscustomobject]@{ Skip = $skip.ToArray(); Unknown = $unknown.ToArray() }
}

function Invoke-MenuHardening {
    # Preview first, then apply only after the user types YES.
    param([Parameter(Mandatory)][scriptblock]$Ask)
    if (-not (Test-IsAdministrator)) {
        Write-Finding -Level Warn -Message 'Hardening needs an Administrator window. Right-click NetSecToolkit.cmd > Run as administrator.'
        return
    }
    Write-Host ''
    Write-Host '  Step 1 of 2: preview. Nothing is changed yet.' -ForegroundColor Cyan
    Set-HardeningBaseline -WhatIf
    Write-Host ''
    Write-Host '  Step 2 of 2: apply.' -ForegroundColor Cyan
    Write-Host '  Type YES to apply all steps, S to choose steps to leave alone, or press Enter to cancel.'
    $answer = & $Ask 'Apply'
    $skip = @()
    if ($answer -eq 'S') {
        $valid = @(Get-HardeningStepName)
        Write-Wrapped -Text ('Step names: ' + ($valid -join ' ')) -Indent 2
        Write-Host '  To keep Remote Desktop: RemoteDesktop. To keep old NAS or printer names working: NetBIOS'
        $parsed = ConvertTo-SkipList -Text (& $Ask 'Steps to leave alone (separate with commas)') -Valid $valid
        if ($parsed.Unknown.Count) {
            Write-Host "  Not a step name: $($parsed.Unknown -join ', '). Nothing was changed; choose H to try again." -ForegroundColor Yellow
            return
        }
        $skip = $parsed.Skip
        $answer = & $Ask "Type YES to apply everything except: $($skip -join ', ')"
    }
    # -ceq: only upper-case YES applies, so a stray "yes" keystroke cannot.
    if ($answer -cne 'YES') {
        Write-Host '  Cancelled. Nothing was changed.' -ForegroundColor Yellow
        return
    }
    if ($skip.Count) { Set-HardeningBaseline -Skip $skip -Confirm:$false } else { Set-HardeningBaseline -Confirm:$false }
    Write-Host '  Restart when convenient, then run the full check (option 1) to confirm.' -ForegroundColor DarkGray
}

function Open-LastReport {
    $dir = Get-DefaultReportDir
    $last = Get-ChildItem -Path $dir -Filter 'Report_*.html' -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if (-not $last) {
        Write-Finding -Level Info -Message "No report yet in $dir. Run the full check (option 1) first."
        return
    }
    Write-Host "  Opening $($last.FullName)"
    Invoke-Item -LiteralPath $last.FullName
}
