Describe 'Private parsers' {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '..' 'NetSecToolkit' 'NetSecToolkit.psd1') -Force
    }

    AfterAll { Remove-Module NetSecToolkit -ErrorAction SilentlyContinue }

    Context 'Get-RiskyPortMatch' {
        It 'matches single risky ports' {
            InModuleScope NetSecToolkit { Get-RiskyPortMatch -Ports '3389' | Should -Be '3389/RDP' }
        }
        It 'matches every risky port inside a range' {
            InModuleScope NetSecToolkit {
                (Get-RiskyPortMatch -Ports '137-139') -join ',' | Should -Be '137/NetBIOS,138/NetBIOS,139/NetBIOS'
            }
        }
        It 'ignores safe ports, Any, and empty input' {
            InModuleScope NetSecToolkit {
                Get-RiskyPortMatch -Ports '80'  | Should -BeNullOrEmpty
                Get-RiskyPortMatch -Ports 'Any' | Should -BeNullOrEmpty
                Get-RiskyPortMatch -Ports $null | Should -BeNullOrEmpty
            }
        }
    }

    Context 'ConvertFrom-NetshWlanInterface' {
        It 'parses a classic Wi-Fi connection' {
            InModuleScope NetSecToolkit {
                $text = @(
                    'There is 1 interface on the system:', '',
                    '    Name                   : Wi-Fi',
                    '    State                  : connected',
                    '    SSID                   : ExampleNet',
                    '    BSSID                  : 00:11:22:33:44:55',
                    '    Band                   : 5 GHz',
                    '    Channel                : 36',
                    '    Connected Akm-cipher   : [ akm = 00-0f-ac:02, cipher = 00-0f-ac:04 ]',
                    '    Radio type             : 802.11ac',
                    '    Authentication         : WPA2-Personal',
                    '    Signal                 : 72%'
                )
                $w = @(ConvertFrom-NetshWlanInterface -Text $text)[0]
                $w.Name                 | Should -Be 'Wi-Fi'
                $w['SSID']              | Should -Be 'ExampleNet'
                $w['BSSID']             | Should -Be '00:11:22:33:44:55'
                $w['Channel']           | Should -Be '36'
                $w['Authentication']    | Should -Be 'WPA2-Personal'
                $w.ContainsKey('_links') | Should -BeFalse
            }
        }

        It 'parses Wi-Fi 7 multi-link (MLO) connections' {
            InModuleScope NetSecToolkit {
                $text = @(
                    '    Name                   : Wi-Fi 2',
                    '    SSID                   : ExampleNet-5G',
                    '    MLD AP BSSID           : 02:11:22:33:44:55',
                    '        LinkID: 0, Local: 00:aa:bb:cc:dd:01, AP: 02:11:22:33:44:55, RSSI: -53, Channel: 48, Band: 5 GHz, BW: 80',
                    '        LinkID: 1, Local: 00:aa:bb:cc:dd:02, AP: 02:11:22:33:44:66, RSSI: -60, Channel: 6, Band: 2.4 GHz, BW: 20',
                    '    Radio type             : 802.11be',
                    '    Authentication         : WPA3-Personal  (H2E)'
                )
                $w = @(ConvertFrom-NetshWlanInterface -Text $text)[0]
                $w['MLD AP BSSID']     | Should -Be '02:11:22:33:44:55'
                $w['_links'].Count     | Should -Be 2
                $w['_links'][0].Channel | Should -Be 48
                $w['_links'][0].Width   | Should -Be 80
                $w['_links'][0].Rssi    | Should -Be -53
                $w['_links'][1].Band    | Should -Be '2.4 GHz'
            }
        }

        It 'separates multiple interfaces' {
            InModuleScope NetSecToolkit {
                $text = @(
                    '    Name                   : Wi-Fi 2', '    State                  : connected',
                    '    Name                   : Wi-Fi 5', '    State                  : disconnected'
                )
                $all = @(ConvertFrom-NetshWlanInterface -Text $text)
                $all.Count          | Should -Be 2
                $all[1]['State']    | Should -Be 'disconnected'
            }
        }
    }

    Context 'ConvertFrom-FirewallLogLine' {
        It 'parses a DROP entry' {
            InModuleScope NetSecToolkit {
                $e = ConvertFrom-FirewallLogLine '2026-01-15 18:00:01 DROP UDP 192.168.1.20 239.255.255.250 49804 1900 417 - - - - - - - RECEIVE 1234'
                $e.Action      | Should -Be 'DROP'
                $e.Protocol    | Should -Be 'UDP'
                $e.Source      | Should -Be '192.168.1.20'
                $e.Destination | Should -Be '239.255.255.250'
                $e.DestPort    | Should -Be '1900'
                $e.Time        | Should -Be ([datetime]'2026-01-15 18:00:01')
            }
        }
        It 'skips headers, blank lines, and malformed lines' {
            InModuleScope NetSecToolkit {
                ConvertFrom-FirewallLogLine '#Version: 1.5'           | Should -BeNullOrEmpty
                ConvertFrom-FirewallLogLine ''                         | Should -BeNullOrEmpty
                ConvertFrom-FirewallLogLine 'not a log line at all ok' | Should -BeNullOrEmpty
            }
        }
    }

    Context 'Get-ServiceRiskNote' {
        It 'gives advice only for open services' {
            InModuleScope NetSecToolkit {
                Get-ServiceRiskNote -Open $false -Risk 'High'     | Should -Be ''
                Get-ServiceRiskNote -Open $true  -Risk 'High'     | Should -Match 'TURN OFF'
                Get-ServiceRiskNote -Open $true  -Risk 'Expected' | Should -Be 'Normal'
            }
        }
    }

    Context 'Speed test math' {
        It 'sizes a test to the target duration within limits' {
            InModuleScope NetSecToolkit {
                Get-TestSize -Mbps 100  -Min 10MB -Max 400MB -Seconds 8 | Should -Be 100000000
                Get-TestSize -Mbps 1    -Min 10MB -Max 400MB -Seconds 8 | Should -Be 10MB
                Get-TestSize -Mbps 5000 -Min 10MB -Max 400MB -Seconds 8 | Should -Be 400MB
            }
        }
        It 'computes median latency and jitter' {
            InModuleScope NetSecToolkit {
                $s = Get-LatencyStat -Samples @(10, 12, 11, 30, 10)
                $s.Median | Should -Be 11
                $s.Jitter | Should -Be 10.5
                Get-LatencyStat -Samples @(5) | Should -BeNullOrEmpty
            }
        }
    }
}
