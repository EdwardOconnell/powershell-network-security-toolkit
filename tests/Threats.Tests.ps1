Describe 'Threat ratings (1.2.0)' {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '..' 'NetSecToolkit' 'NetSecToolkit.psd1') -Force
    }

    AfterAll { Remove-Module NetSecToolkit -ErrorAction SilentlyContinue }

    It 'rates a hardened, updated PC as protected against all seven threats' {
        InModuleScope NetSecToolkit {
            $state = [pscustomobject]@{
                FirewallOn = $true; Smb1 = $false; ServerRunning = $true; SmbRuleOpen = $false
                RdpOn = $false; RdpNla = $false; RdpRuleOpen = $false; AutoRunOff = $true
                GuestOff = $true; Lockout = $true; AnonBlocked = $true; NoLm = $true; Ntlm2 = $true
                LsaProtection = $true; UacOn = $true; UpdateDays = 10
                Antivirus = @([pscustomobject]@{ Name = 'Microsoft Defender'; RealTime = $true; UpToDate = $true })
            }
            $r = @(Get-ThreatRatingList -State $state)
            $r.Count | Should -Be 7
            @($r | Where-Object Rating -ne 'Protected').Count | Should -Be 0
        }
    }

    It 'rates an open, unpatched PC as exposed' {
        InModuleScope NetSecToolkit {
            $state = [pscustomobject]@{
                FirewallOn = $false; Smb1 = $true; ServerRunning = $true; SmbRuleOpen = $true
                RdpOn = $true; RdpNla = $false; RdpRuleOpen = $true; AutoRunOff = $false
                GuestOff = $false; Lockout = $false; AnonBlocked = $false; NoLm = $false; Ntlm2 = $false
                LsaProtection = $false; UacOn = $false; UpdateDays = 300; Antivirus = @()
            }
            $r = @(Get-ThreatRatingList -State $state)
            @($r | Where-Object Rating -eq 'Exposed').Count | Should -Be 6
            # AutoPlay left on is a low-risk default on Windows 7 and later, not an exposure.
            ($r | Where-Object Threat -match 'USB').Rating | Should -Be 'Partly'
            ($r | Where-Object Threat -match 'USB').Inherent | Should -BeTrue
        }
    }

    It 'treats SMBv1 behind a closed firewall as partly protected' {
        InModuleScope NetSecToolkit {
            $state = [pscustomobject]@{
                FirewallOn = $true; Smb1 = $true; ServerRunning = $true; SmbRuleOpen = $false
                RdpOn = $true; RdpNla = $true; RdpRuleOpen = $true; AutoRunOff = $true
                GuestOff = $true; Lockout = $true; AnonBlocked = $true; NoLm = $true; Ntlm2 = $true
                LsaProtection = $false; UacOn = $true; UpdateDays = 60
                Antivirus = @([pscustomobject]@{ Name = 'Microsoft Defender'; RealTime = $true; UpToDate = $false })
            }
            $r = @(Get-ThreatRatingList -State $state)
            ($r | Where-Object Threat -match 'SMB').Rating | Should -Be 'Partly'
            ($r | Where-Object Threat -match 'Remote Desktop').Rating | Should -Be 'Partly'
            ($r | Where-Object Threat -match 'Password theft').Rating | Should -Be 'Partly'
            ($r | Where-Object Threat -match 'Ransomware').Why | Should -Match 'out of date'
            ($r | Where-Object Threat -match 'Unpatched').Rating | Should -Be 'Partly'
        }
    }

    It 'says Unknown when SMBv1 or the update date cannot be read' {
        InModuleScope NetSecToolkit {
            $state = [pscustomobject]@{
                FirewallOn = $true; Smb1 = $null; ServerRunning = $false; SmbRuleOpen = $false
                RdpOn = $false; RdpNla = $false; RdpRuleOpen = $false; AutoRunOff = $true
                GuestOff = $true; Lockout = $true; AnonBlocked = $true; NoLm = $true; Ntlm2 = $true
                LsaProtection = $true; UacOn = $true; UpdateDays = $null
                Antivirus = @([pscustomobject]@{ Name = 'Other AV'; RealTime = $true; UpToDate = $true })
            }
            $r = @(Get-ThreatRatingList -State $state)
            ($r | Where-Object Threat -match 'SMB').Rating | Should -Be 'Unknown'
            ($r | Where-Object Threat -match 'Unpatched').Rating | Should -Be 'Unknown'
        }
    }

    It 'maps ratings to finding levels' {
        InModuleScope NetSecToolkit {
            ConvertTo-ThreatLevel -Rating Exposed -Inherent $false | Should -Be 'Risk'
            ConvertTo-ThreatLevel -Rating Exposed -Inherent $true | Should -Be 'Info'
            ConvertTo-ThreatLevel -Rating Partly -Inherent $false | Should -Be 'Warn'
            ConvertTo-ThreatLevel -Rating Partly -Inherent $true | Should -Be 'Info'
            ConvertTo-ThreatLevel -Rating Unknown -Inherent $false | Should -Be 'Info'
            ConvertTo-ThreatLevel -Rating Protected -Inherent $false | Should -Be 'OK'
        }
    }
}
