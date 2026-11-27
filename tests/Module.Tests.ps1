Describe 'NetSecToolkit' {
    BeforeAll {
        $script:ModulePath = Join-Path $PSScriptRoot '..' 'NetSecToolkit' 'NetSecToolkit.psd1'
        Import-Module $script:ModulePath -Force
        $script:Expected = @(
            'Find-MalwareIndicator', 'Find-NetworkDevice', 'Get-AccountAudit', 'Get-FirewallAudit',
            'Get-FirewallLog', 'Get-HardeningStatus', 'Get-NetAdapterHealth', 'Get-ThreatExposure',
            'Get-USBHistory', 'Invoke-DailySecurityCheck', 'Invoke-NetSecAssistant', 'Set-FirewallBaseline',
            'Set-HardeningBaseline', 'Start-NetSecToolkit', 'Test-NetworkSpeed', 'Test-RouterExposure'
        )
    }

    AfterAll { Remove-Module NetSecToolkit -ErrorAction SilentlyContinue }

    Context 'Module' {
        It 'has a valid manifest' {
            { Test-ModuleManifest -Path $script:ModulePath -ErrorAction Stop } | Should -Not -Throw
        }

        It 'exports exactly the public commands' {
            $exported = @((Get-Command -Module NetSecToolkit -CommandType Function).Name | Sort-Object)
            $exported -join ',' | Should -Be (($script:Expected | Sort-Object) -join ',')
        }

        It 'exports the nsai alias for the assistant' {
            (Get-Module NetSecToolkit).ExportedAliases.Keys -join ',' | Should -Be 'nsai'
            (Get-Alias nsai).Definition | Should -Be 'Invoke-NetSecAssistant'
        }

        It 'does not export private helpers' {
            Get-Command -Module NetSecToolkit -Name 'ConvertTo-UInt32' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
            Get-Command -Module NetSecToolkit -Name 'New-Finding' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
            Get-Command -Module NetSecToolkit -Name 'Invoke-ClaudeApi' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It 'declares the same version in the manifest and the module' {
            $manifest = Import-PowerShellDataFile -Path $script:ModulePath
            InModuleScope NetSecToolkit { $script:ToolkitVersion } | Should -Be $manifest.ModuleVersion
        }

        It 'supports -WhatIf and -Confirm on the commands that change settings' {
            foreach ($name in 'Set-FirewallBaseline', 'Set-HardeningBaseline') {
                $cmd = Get-Command $name
                $cmd.Parameters.ContainsKey('WhatIf')  | Should -BeTrue
                $cmd.Parameters.ContainsKey('Confirm') | Should -BeTrue
            }
        }

        It 'only lets Set- commands change settings' {
            $changing = @(Get-Command -Module NetSecToolkit -CommandType Function |
                Where-Object { $_.Parameters.ContainsKey('WhatIf') }).Name | Sort-Object
            $changing -join ',' | Should -Be 'Set-FirewallBaseline,Set-HardeningBaseline'
        }

        It 'offers a -Skip name for every hardening step, and nothing else' {
            InModuleScope NetSecToolkit { (Get-HardeningStepName) -join ',' } |
                Should -Be 'Firewall,Logging,RemoteAssistance,RemoteDesktop,RemoteRegistry,LegacyServices,SMBv1,NetBIOS,Guest,RestrictAnonymous,NoLMHash,NTLMv2,PasswordPolicy,AutoRun'
        }

        It 'ships no API key' {
            $source = (Get-ChildItem (Join-Path $PSScriptRoot '..' 'NetSecToolkit') -Recurse -Filter '*.ps1' | Get-Content -Raw) -join "`n"
            $source | Should -Not -Match 'sk-ant-'
        }

        It 'has a synopsis and an example for every public command' {
            foreach ($name in $script:Expected) {
                $help = Get-Help $name -Full
                $help.Synopsis | Should -Not -BeNullOrEmpty
                $help.Synopsis | Should -Not -Match "^\s*$name"
                @($help.Examples.Example).Count | Should -BeGreaterThan 0
            }
        }
    }
}
