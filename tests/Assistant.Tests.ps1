Describe 'Assistant and findings (1.2.0)' {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '..' 'NetSecToolkit' 'NetSecToolkit.psd1') -Force
    }

    AfterAll { Remove-Module NetSecToolkit -ErrorAction SilentlyContinue }

    Context 'Findings' {
        It 'creates findings with the four fields' {
            InModuleScope NetSecToolkit {
                $f = New-Finding -Area Firewall -Level Warn -Message 'm' -Fix 'f' -Quiet
                ($f.PSObject.Properties.Name -join ',') | Should -Be 'Area,Level,Message,Fix'
            }
        }
        It 'adds to an empty list and counts by level' {
            InModuleScope NetSecToolkit {
                $list = [System.Collections.Generic.List[object]]::new()
                Add-Finding $list Firewall Risk 'a' 'fix' 6>$null
                Add-Finding $list Firewall Warn 'b' 6>$null
                Add-Finding $list Firewall OK 'c' 6>$null
                Add-FindingRange $list @($null, (New-Finding -Area USB -Level Info -Message 'd' -Quiet))
                $c = Get-FindingCount $list
                "$($c.Risk),$($c.Warn),$($c.Info),$($c.OK),$($c.Total)" | Should -Be '1,1,1,1,4'
            }
        }
        It 'turns 1.x warning strings into findings' {
            InModuleScope NetSecToolkit {
                $f = @(ConvertTo-WarningFinding -Area Network -Warning 'DNS lookups are failing.', '' -Fix 'x')
                $f.Count | Should -Be 1
                $f[0].Level | Should -Be 'Warn'
                (ConvertTo-WarningFinding -Area Network -Warning @() -OkMessage 'All good').Level | Should -Be 'OK'
            }
        }
        It 'writes an HTML report that escapes text and lists risks first' {
            InModuleScope NetSecToolkit {
                $path = Join-Path ([System.IO.Path]::GetTempPath()) "nst_$([guid]::NewGuid().ToString('N')).html"
                $findings = @(
                    New-Finding -Area Test -Level OK -Message 'fine' -Quiet
                    New-Finding -Area Test -Level Risk -Message 'Shell is "a.exe" <script>alert(1)</script>' -Fix 'reg add "HKLM\x" & more' -Quiet
                    New-Finding -Area Test -Level Warn -Message 'warned' -Quiet
                )
                try {
                    Export-FindingHtml -Finding $findings -Path $path -Title 'Report <1>' -Note 'note' -Plan "1. [Risk] do this`n     Fix: run that"
                    $html = Get-Content -LiteralPath $path -Raw
                } finally {
                    Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
                }
                $html | Should -Match '<title>Report &lt;1&gt;</title>'
                $html | Should -Not -Match '<script>'
                $html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
                $html | Should -Match '1 risk\(s\), 1 warning\(s\)</b>, 3 finding\(s\)'
                $html | Should -Match 'Fix: <code>run that</code>'
                Export-FindingHtml -Finding $findings -Path $path -Title 'T' -Plan "1. [Warn] a`n     Fix: do x`n     Same fix for: b; c."
                $html2 = Get-Content -LiteralPath $path -Raw
                Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
                $html2 | Should -Match 'Fix: <code>do x</code><br>Same fix for: b; c\.'
                $html.IndexOf('class="risk"') | Should -BeLessThan $html.IndexOf('class="warn"')
                $html.IndexOf('class="warn"') | Should -BeLessThan $html.IndexOf('class="ok"')
            }
        }
    }

    Context 'Offline notes' {
        It 'has a complete, uniquely named entry for every topic' {
            InModuleScope NetSecToolkit {
                $script:AssistantKB.Count | Should -BeGreaterThan 35
                foreach ($t in $script:AssistantKB) {
                    $t.Id | Should -Not -BeNullOrEmpty
                    $t.Title | Should -Not -BeNullOrEmpty
                    $t.Text | Should -Not -BeNullOrEmpty
                    $t.Do | Should -Not -BeNullOrEmpty
                    @($t.Words).Count | Should -BeGreaterThan 0
                    foreach ($w in $t.Words) { $w | Should -BeExactly $w.ToLower() }
                }
                @($script:AssistantKB.Id | Sort-Object -Unique).Count | Should -Be $script:AssistantKB.Count
            }
        }
        It 'only names commands and hardening steps that exist' {
            InModuleScope NetSecToolkit {
                $text = ($script:AssistantKB | ForEach-Object { "$($_.Text) $($_.Do)" }) -join ' '
                $exported = (Get-Command -Module NetSecToolkit -CommandType Function).Name
                $named = [regex]::Matches($text, '\b(Get|Set|Find|Test|Invoke|Start)-(NetAdapterHealth|[A-Z][A-Za-z]*(Audit|Status|Baseline|Log|History|Exposure|Indicator|Device|Speed|Check|Assistant|Toolkit))\b') |
                    ForEach-Object Value | Sort-Object -Unique
                @($named).Count | Should -BeGreaterThan 10
                foreach ($n in $named) { $exported | Should -Contain $n }
                $steps = @(Get-HardeningStepName)
                $whatif = ($script:AssistantKB | Where-Object Id -eq 'whatif').Text
                foreach ($s in $steps) { $whatif | Should -Match "\b$s\b" }
            }
        }
        It 'matches questions to the right topic' {
            InModuleScope NetSecToolkit {
                $cases = [ordered]@{
                    'what is netbios'                      = 'netbios'
                    'why turn off smbv1?'                  = 'smb'
                    'what is 445'                          = 'smb'
                    'is remote desktop safe'               = 'rdp'
                    'how do I undo the hardening'          = 'undo'
                    'how do i use claude mode'             = 'assistant'
                    'what does the hosts file do'          = 'hosts'
                    'is my pc infected with a virus'       = 'malware'
                    'what is uac'                          = 'uac'
                    'tell me about windows update'         = 'updates'
                    'what are defender exclusions'         = 'antivirus'
                    'someone plugged in a usb drive'       = 'usb'
                }
                foreach ($q in $cases.Keys) {
                    (@(Get-AssistantTopic $q) | Select-Object -First 1).Id | Should -Be $cases[$q]
                }
            }
        }
        It 'does not match short words inside longer ones' {
            InModuleScope NetSecToolkit {
                @(Get-AssistantTopic 'tell me a joke').Count | Should -Be 0
                # "dep" must not match "independent"; "rdp" must not match "wordpress".
                @(Get-AssistantTopic 'independent wordpress') | Where-Object { $_.Id -in 'dep', 'rdp' } | Should -BeNullOrEmpty
            }
        }
    }

    Context 'Fix plan' {
        It 'says so when there is nothing to fix' {
            InModuleScope NetSecToolkit {
                $plan = @(Get-AssistantFixPlan -Finding @(New-Finding -Area A -Level OK -Message 'ok' -Quiet))
                $plan.Count | Should -Be 1
                $plan[0] | Should -Match '^Nothing to fix'
            }
        }
        It 'puts own-fix risks first, then one baseline run, then warnings, then the re-check' {
            InModuleScope NetSecToolkit {
                $findings = @(
                    New-Finding -Area Logon -Level Warn -Message 'Guest is enabled.' -Fix 'Set-HardeningBaseline' -Quiet
                    New-Finding -Area SMB -Level Risk -Message 'SMBv1 is ON.' -Fix 'Set-HardeningBaseline' -Quiet
                    New-Finding -Area Ports -Level Warn -Message 'WinRM is listening.' -Fix 'Disable-PSRemoting -Force' -Quiet
                    New-Finding -Area UAC -Level Risk -Message 'UAC is off.' -Fix 'Turn UAC on' -Quiet
                    New-Finding -Area Ports -Level Info -Message 'ignored' -Quiet
                )
                $plan = @(Get-AssistantFixPlan -Finding $findings)
                $plan.Count | Should -Be 4
                $plan[0] | Should -Match '^1\. \[Risk\] UAC is off\.'
                $plan[1] | Should -Match '^2\. Run Set-HardeningBaseline -WhatIf to preview'
                $plan[1] | Should -Match 'fixes 2 item\(s\)'
                $plan[2] | Should -Match '^3\. \[Warn\] WinRM is listening\.'
                $plan[3] | Should -Match '^4\. Then run Get-HardeningStatus'
            }
        }
        It 'lists one step per distinct fix' {
            InModuleScope NetSecToolkit {
                $findings = @(
                    New-Finding -Area Updates -Level Risk -Message 'No update in 200 days.' -Fix 'Check for updates' -Quiet
                    New-Finding -Area Threats -Level Risk -Message 'Unpatched Windows flaws: EXPOSED.' -Fix 'Check for updates' -Quiet
                )
                $plan = @(Get-AssistantFixPlan -Finding $findings)
                $plan.Count | Should -Be 2   # one fix + the re-check line
                # The second finding is not dropped: it is named under the first.
                $plan[0] | Should -Match 'Same fix for: Unpatched Windows flaws: EXPOSED\.'
            }
        }
        It 'numbers issues with risks first, in the order found' {
            InModuleScope NetSecToolkit {
                $findings = @(
                    New-Finding -Area A -Level Info -Message 'i1' -Quiet
                    New-Finding -Area A -Level Warn -Message 'w1' -Quiet
                    New-Finding -Area A -Level OK -Message 'ok' -Quiet
                    New-Finding -Area A -Level Risk -Message 'r1' -Quiet
                    New-Finding -Area A -Level Warn -Message 'w2' -Quiet
                )
                (@(Get-AssistantIssueList $findings).Message -join ',') | Should -Be 'r1,w1,w2,i1'
            }
        }
    }

    Context 'Scan requests' {
        It 'recognizes plain-language requests to run a check' {
            InModuleScope NetSecToolkit {
                foreach ($q in 'scan', 'rescan', 'check', 'check my settings', 'Check my PC', 'scan this computer',
                               'please check my security', 'can you scan my pc?', 'run a scan', 'run the check again', 'audit everything.') {
                    Test-AssistantScanRequest $q | Should -BeTrue
                }
            }
        }
        It 'leaves questions about one thing alone' {
            InModuleScope NetSecToolkit {
                foreach ($q in 'check the firewall log', 'what is netbios', 'how do I check my router', 'scan results', 'plan', 'checkmate', '') {
                    Test-AssistantScanRequest $q | Should -BeFalse
                }
            }
        }
    }

    Context 'Turns' {
        It 'answers summary, list, explain and questions offline' {
            InModuleScope NetSecToolkit {
                $state = @{ Mode = 'Offline'; Model = 'm'; Sources = @('test'); History = @(); NoRedact = $false
                    Findings = @(
                        New-Finding -Area SMB -Level Risk -Message 'The SMBv1 server protocol is ON.' -Fix 'Set-HardeningBaseline' -Quiet
                        New-Finding -Area Firewall -Level OK -Message 'Firewall is on.' -Quiet
                    ) }
                Invoke-AssistantTurn -State $state -Line 'summary' 6>$null | Should -Match '1 risk\(s\), 0 warning\(s\)'
                Invoke-AssistantTurn -State $state -Line 'list' 6>$null | Should -Match '1\. \[Risk\] SMB: The SMBv1'
                $explain = Invoke-AssistantTurn -State $state -Line 'explain 1' 6>$null
                $explain | Should -Match 'What it means: SMB is Windows file and printer sharing'
                $explain | Should -Match 'Fix: Set-HardeningBaseline'
                Invoke-AssistantTurn -State $state -Line 'explain 7' 6>$null | Should -Match 'There is no issue #7'
                Invoke-AssistantTurn -State $state -Line 'what is netbios' 6>$null | Should -Match '^NetBIOS over TCP/IP'
                Invoke-AssistantTurn -State $state -Line 'what should I fix first?' 6>$null | Should -Match 'Run Set-HardeningBaseline -WhatIf'
                Invoke-AssistantTurn -State $state -Line 'help' 6>$null | Should -Match 'explain <n>'
            }
        }
    }

    Context 'Claude mode' {
        BeforeAll { $script:SavedKey = $env:ANTHROPIC_API_KEY }
        AfterAll  {
            $env:ANTHROPIC_API_KEY = $script:SavedKey
            Remove-Variable -Name NstCaptured -Scope Global -ErrorAction SilentlyContinue
        }

        It 'masks MAC addresses, the PC name and the user name' {
            InModuleScope NetSecToolkit {
                $t = Protect-AssistantText -Text 'EDDIE-PC user Edward at AA-BB-CC-DD-EE-FF and aa:bb:cc:dd:ee:ff' -ComputerName 'EDDIE-PC' -UserName 'Edward'
                $t | Should -Be '<PC-NAME> user <USER> at xx-xx-xx-xx-xx-xx and xx-xx-xx-xx-xx-xx'
            }
        }
        It 'keeps built-in account names readable' {
            InModuleScope NetSecToolkit {
                Protect-AssistantText -Text 'The Administrator account' -ComputerName 'PC1' -UserName 'Administrator' | Should -Be 'The Administrator account'
            }
        }
        It 'refuses to call the API without a key, and stays offline' {
            $env:ANTHROPIC_API_KEY = ''
            InModuleScope NetSecToolkit {
                { Invoke-ClaudeApi -Model 'm' -System 's' -Message @(@{ role = 'user'; content = 'q' }) } | Should -Throw
                $state = @{ Mode = 'Offline'; Model = 'm'; Findings = @(); Sources = @(); History = @(); NoRedact = $false }
                Invoke-AssistantTurn -State $state -Line 'mode claude' 6>$null | Should -Match 'needs your API key'
                $state.Mode | Should -Be 'Offline'
            }
        }
        It 'sends the masked question and findings, and never the key, in the request body' {
            $env:ANTHROPIC_API_KEY = 'unit-test-key-000'
            InModuleScope NetSecToolkit {
                Mock Invoke-RestMethod {
                    $global:NstCaptured = @{ Body = $Body; Headers = $Headers }
                    [pscustomobject]@{ content = @([pscustomobject]@{ type = 'text'; text = 'Turn SMBv1 off.' }); stop_reason = 'end_turn' }
                }
                Mock Get-OsInfo { [pscustomobject]@{ Caption = 'Microsoft Windows 11 Pro'; Version = '10.0.26100' } }
                $state = @{ Mode = 'Claude'; Model = 'test-model'; Sources = @('test'); History = @(); NoRedact = $false
                    Findings = @(New-Finding -Area Devices -Level Warn -Message 'New device 00-11-22-33-44-55' -Quiet) }
                $answer = Invoke-AssistantTurn -State $state -Line 'who is 00-11-22-33-44-55?' 6>$null
                $answer | Should -Be 'Turn SMBv1 off.'
                $global:NstCaptured.Body | Should -Not -Match 'unit-test-key-000'
                $global:NstCaptured.Body | Should -Not -Match '00-11-22-33-44-55'
                $global:NstCaptured.Body | Should -Match 'xx-xx-xx-xx-xx-xx'
                $global:NstCaptured.Body | Should -Match '"model":"test-model"'
                $global:NstCaptured.Headers['anthropic-version'] | Should -Be '2023-06-01'
                $state.History.Count | Should -Be 2
                $state.History[1].role | Should -Be 'assistant'
            }
        }
        It 'falls back to the offline notes when the API fails, without leaking the key' {
            $env:ANTHROPIC_API_KEY = 'unit-test-key-000'
            InModuleScope NetSecToolkit {
                Mock Invoke-RestMethod { throw 'The remote name could not be resolved' }
                Mock Get-OsInfo { $null }
                { Invoke-ClaudeApi -Model 'm' -System 's' -Message @(@{ role = 'user'; content = 'q' }) } | Should -Throw
                $err = try { Invoke-ClaudeApi -Model 'm' -System 's' -Message @(@{ role = 'user'; content = 'q' }) } catch { "$_" }
                $err | Should -Match '^Claude API error'
                $err | Should -Not -Match 'unit-test-key-000'
                $state = @{ Mode = 'Claude'; Model = 'm'; Findings = @(); Sources = @(); History = @(); NoRedact = $false }
                Invoke-AssistantTurn -State $state -Line 'what is netbios' 6>$null | Should -Match '^NetBIOS over TCP/IP'
            }
        }
    }

    Context 'Menu' {
        It 'accepts step names in any case and reports the ones that are not steps' {
            InModuleScope NetSecToolkit {
                $r = ConvertTo-SkipList -Text 'remotedesktop, NetBIOS  bogus' -Valid 'RemoteDesktop', 'NetBIOS', 'Guest'
                $r.Skip -join ',' | Should -Be 'RemoteDesktop,NetBIOS'
                $r.Unknown -join ',' | Should -Be 'bogus'
                (ConvertTo-SkipList -Text '' -Valid 'Guest').Skip.Count | Should -Be 0
            }
        }
    }
}
