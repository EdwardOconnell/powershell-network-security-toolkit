function Start-NetSecToolkit {
    <#
    .SYNOPSIS
        Menu for the whole toolkit. NetSecToolkit.cmd opens this.
    .DESCRIPTION
        Shows a menu of the checks, the hardening run (always previewed first and
        applied only after you type YES), the assistant and the last report, so the
        toolkit can be used without typing commands. Errors in one option are shown
        and the menu carries on. The menu itself changes nothing.
    .EXAMPLE
        Start-NetSecToolkit
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Opens a menu. The only option that changes settings previews with -WhatIf and asks for YES first.')]
    [CmdletBinding()]
    param()

    Assert-Windows
    try { $Host.UI.RawUI.WindowTitle = "NetSecToolkit $script:ToolkitVersion" }
    catch { Write-Verbose 'Could not set the window title.' }

    $ask = { param([string]$Prompt) "$(Read-Host $Prompt)".Trim() }

    while ($true) {
        Show-ToolkitMenu
        Write-Host ''
        $choice = (& $ask 'Choose').ToUpper()
        $wait = $true
        try {
            switch ($choice) {
                '1' { Invoke-DailySecurityCheck }
                '2' { Get-HardeningStatus }
                '3' { Get-FirewallAudit }
                '4' { Get-AccountAudit }
                '5' { Get-FirewallLog }
                '6' {
                    $sweep = & $ask 'Ping every address on the subnet too? Only on a network you own or may scan. (Y/N)'
                    if ($sweep -eq 'Y') { Find-NetworkDevice } else { Find-NetworkDevice -Passive }
                }
                '7' { Test-RouterExposure }
                '8' { Get-NetAdapterHealth }
                '9' { Get-USBHistory }
                'V' {
                    Get-ThreatExposure
                    $dir = Get-DefaultReportDir
                    New-Item -ItemType Directory -Path $dir -Force | Out-Null
                    Find-MalwareIndicator -ExportPath (Join-Path $dir "Hashes_$(Get-Date -Format 'yyyy-MM-dd_HHmm').csv")
                }
                'S' { Test-NetworkSpeed }
                'H' { Invoke-MenuHardening -Ask $ask }
                'A' { Invoke-NetSecAssistant; $wait = $false }
                'R' { Open-LastReport }
                'P' {
                    Write-Host '  Type exit to come back to the menu. Get-Help <command> -Full explains any command.' -ForegroundColor DarkGray
                    $wait = $false
                    $Host.EnterNestedPrompt()
                }
                'Q' { return }
                ''  { $wait = $false }
                default { Write-Host "  `"$choice`" is not on the menu." -ForegroundColor Yellow }
            }
        } catch {
            Write-Host ''
            Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host '  The menu is still running.' -ForegroundColor DarkGray
        }
        if ($wait) {
            Write-Host ''
            $null = Read-Host 'Press Enter to go back to the menu'
        }
    }
}
