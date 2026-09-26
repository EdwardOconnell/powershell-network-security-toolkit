Describe 'NetSecToolkit' {
    BeforeAll {
        $script:ModulePath = Join-Path $PSScriptRoot '..' 'NetSecToolkit' 'NetSecToolkit.psd1'
        Import-Module $script:ModulePath -Force
        $script:Expected = @(
            'Find-NetworkDevice', 'Get-FirewallAudit', 'Get-NetAdapterHealth',
            'Invoke-DailySecurityCheck', 'Set-FirewallBaseline', 'Test-NetworkSpeed', 'Test-RouterExposure'
        )
    }

    AfterAll { Remove-Module NetSecToolkit -ErrorAction SilentlyContinue }

    Context 'Module' {
        It 'has a valid manifest' {
            { Test-ModuleManifest -Path $script:ModulePath -ErrorAction Stop } | Should -Not -Throw
        }

        It 'exports exactly the public commands' {
            $exported = @((Get-Command -Module NetSecToolkit).Name | Sort-Object)
            $exported -join ',' | Should -Be (($script:Expected | Sort-Object) -join ',')
        }

        It 'does not export private helpers' {
            Get-Command -Module NetSecToolkit -Name 'ConvertTo-UInt32' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It 'supports -WhatIf and -Confirm on the command that changes settings' {
            $cmd = Get-Command Set-FirewallBaseline
            $cmd.Parameters.ContainsKey('WhatIf')  | Should -BeTrue
            $cmd.Parameters.ContainsKey('Confirm') | Should -BeTrue
        }

        It 'only lets Set- commands change settings' {
            $changing = @(Get-Command -Module NetSecToolkit | Where-Object { $_.Parameters.ContainsKey('WhatIf') }).Name
            $changing -join ',' | Should -Be 'Set-FirewallBaseline'
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
