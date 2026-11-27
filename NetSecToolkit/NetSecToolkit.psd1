@{
    RootModule           = 'NetSecToolkit.psm1'
    ModuleVersion        = '1.2.2'
    GUID                 = '79f44595-becd-4a7e-95a1-81426804d1b4'
    Author               = "Edward O'Connell III"
    Copyright            = "(c) 2026 Edward O'Connell III. MIT License."
    Description          = 'PowerShell 7 tools for auditing and hardening a Windows PC and its network: firewall, hardening baseline, accounts, firewall log, local devices, router exposure, USB history, threat exposure, signs of malware and connection speed, with a daily check, an HTML report and a built-in assistant.'
    PowerShellVersion    = '7.0'
    CompatiblePSEditions = @('Core')

    FunctionsToExport    = @(
        'Find-MalwareIndicator'
        'Find-NetworkDevice'
        'Get-AccountAudit'
        'Get-FirewallAudit'
        'Get-FirewallLog'
        'Get-HardeningStatus'
        'Get-NetAdapterHealth'
        'Get-ThreatExposure'
        'Get-USBHistory'
        'Invoke-DailySecurityCheck'
        'Invoke-NetSecAssistant'
        'Set-FirewallBaseline'
        'Set-HardeningBaseline'
        'Start-NetSecToolkit'
        'Test-NetworkSpeed'
        'Test-RouterExposure'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @('nsai')

    PrivateData          = @{
        PSData = @{
            Tags       = @('Security', 'Network', 'Firewall', 'Audit', 'Hardening', 'Windows', 'Cybersecurity')
            LicenseUri = 'https://github.com/EdwardOconnell/powershell-network-security-toolkit/blob/main/LICENSE'
            ProjectUri = 'https://github.com/EdwardOconnell/powershell-network-security-toolkit'
        }
    }
}
