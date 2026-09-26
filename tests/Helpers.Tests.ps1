Describe 'Private helpers' {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '..' 'NetSecToolkit' 'NetSecToolkit.psd1') -Force
    }

    AfterAll { Remove-Module NetSecToolkit -ErrorAction SilentlyContinue }

    Context 'IP address conversion' {
        It 'converts an address to a number and back' {
            InModuleScope NetSecToolkit {
                ConvertTo-UInt32 '192.168.1.10' | Should -Be 3232235786
                ConvertTo-IPAddressString 3232235786 | Should -Be '192.168.1.10'
            }
        }
    }

    Context 'Get-SubnetRange' {
        It 'returns the usable range of a /24' {
            InModuleScope NetSecToolkit {
                $r = Get-SubnetRange -IPAddress '192.168.1.57' -PrefixLength 24
                $r.Cidr      | Should -Be '192.168.1.0/24'
                $r.HostCount | Should -Be 254
                ConvertTo-IPAddressString $r.First | Should -Be '192.168.1.1'
                ConvertTo-IPAddressString $r.Last  | Should -Be '192.168.1.254'
                $r.Narrowed  | Should -BeFalse
            }
        }

        It 'narrows large subnets to the /24 around the address' {
            InModuleScope NetSecToolkit {
                $r = Get-SubnetRange -IPAddress '10.20.37.200' -PrefixLength 20
                $r.Cidr     | Should -Be '10.20.37.0/24'
                $r.Narrowed | Should -BeTrue
            }
        }

        It 'handles a /30' {
            InModuleScope NetSecToolkit {
                $r = Get-SubnetRange -IPAddress '172.16.5.9' -PrefixLength 30
                $r.HostCount | Should -Be 2
                ConvertTo-IPAddressString $r.First | Should -Be '172.16.5.9'
                ConvertTo-IPAddressString $r.Last  | Should -Be '172.16.5.10'
            }
        }
    }

    Context 'Test-RandomizedMac' {
        It 'flags locally administered (private) MACs' {
            InModuleScope NetSecToolkit {
                Test-RandomizedMac 'DA-11-22-33-44-55' | Should -BeTrue
                Test-RandomizedMac '7A-11-22-33-44-55' | Should -BeTrue
                Test-RandomizedMac '00-11-22-33-44-55' | Should -BeFalse
                Test-RandomizedMac ''                  | Should -BeFalse
            }
        }
    }

    Context 'Test-DeviceDisabled' {
        It 'recognizes devices disabled in Device Manager' {
            InModuleScope NetSecToolkit {
                Test-DeviceDisabled ([pscustomobject]@{ Problem = 'CM_PROB_DISABLED' }) | Should -BeTrue
                Test-DeviceDisabled ([pscustomobject]@{ Problem = 'CM_PROB_NONE' })     | Should -BeFalse
            }
        }
    }
}
