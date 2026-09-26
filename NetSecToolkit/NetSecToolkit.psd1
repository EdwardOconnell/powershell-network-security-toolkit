@{
    RootModule           = 'NetSecToolkit.psm1'
    ModuleVersion        = '1.1.0'
    GUID                 = '79f44595-becd-4a7e-95a1-81426804d1b4'
    Author               = "Edward O'Connell III"
    Copyright            = "(c) 2026 Edward O'Connell III. MIT License."
    Description          = 'PowerShell 7 tools for auditing a Windows PC and its network (firewall, adapters, local devices, router exposure, connection speed), plus a firewall baseline fix.'
    PowerShellVersion    = '7.0'
    CompatiblePSEditions = @('Core')

    FunctionsToExport    = @(
        'Find-NetworkDevice'
        'Get-FirewallAudit'
        'Get-NetAdapterHealth'
        'Invoke-DailySecurityCheck'
        'Set-FirewallBaseline'
        'Test-NetworkSpeed'
        'Test-RouterExposure'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags       = @('Security', 'Network', 'Firewall', 'Audit', 'Windows', 'Cybersecurity')
            LicenseUri = 'https://github.com/EdwardOconnell/powershell-network-security-toolkit/blob/main/LICENSE'
            ProjectUri = 'https://github.com/EdwardOconnell/powershell-network-security-toolkit'
        }
    }
}
