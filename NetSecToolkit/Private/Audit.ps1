# Helpers for the audit commands added in 1.2.0 (hardening, accounts, firewall log,
# USB history, threat exposure, malware indicators). Not exported.
# System reads go through small wrappers so the logic above them can be unit tested.

$script:LsaPath      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$script:WinlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$script:TsPath       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$script:ExplorerPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$script:Ipv4Pattern  = '^\d{1,3}(\.\d{1,3}){3}$'

#region Registry wrappers

function Get-RegValue {
    # One registry value, or $null if the key or value does not exist.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    $key = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $key) { return $null }
    $prop = $key.PSObject.Properties[$Name]
    if ($prop) { $prop.Value }
}

function Get-RegValueTable {
    # Every value under a key as an ordered name -> value table (empty if the key is missing).
    param([Parameter(Mandatory)][string]$Path)
    $table = [ordered]@{}
    $key = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -ne $key) {
        foreach ($p in $key.PSObject.Properties) {
            if ($p.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { $table[$p.Name] = $p.Value }
        }
    }
    $table
}

function Get-RegSubKeyName {
    # Names of the subkeys of a key (nothing if the key is missing).
    param([Parameter(Mandatory)][string]$Path)
    Get-ChildItem -LiteralPath $Path -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName }
}

function Set-RegDword {
    # Creates the key if needed and writes a DWORD value. Callers handle ShouldProcess.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Only called from Set-HardeningBaseline, inside its ShouldProcess check.')]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][int]$Value)
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

#endregion

#region Pure helpers (unit tested)

function Test-PrivateIPv4 {
    # RFC 1918, CGNAT (100.64/10), link-local and loopback.
    param([string]$Address)
    if ($Address -notmatch $script:Ipv4Pattern) { return $false }
    $o = $Address.Split('.')
    $a = [int]$o[0]; $b = [int]$o[1]
    if ($a -eq 10 -or $a -eq 127) { return $true }
    if ($a -eq 172 -and $b -ge 16 -and $b -le 31) { return $true }
    if ($a -eq 192 -and $b -eq 168) { return $true }
    if ($a -eq 169 -and $b -eq 254) { return $true }
    if ($a -eq 100 -and $b -ge 64 -and $b -le 127) { return $true }
    $false
}

function Test-InLocalNetwork {
    # True if the IPv4 address is inside one of the given networks
    # (objects with Net and Mask as UInt32). Unparseable addresses count as local.
    param([string]$Address, $Network)
    try { $n = ConvertTo-UInt32 $Address } catch { return $true }
    foreach ($ln in @($Network)) {
        if (($n -band $ln.Mask) -eq $ln.Net) { return $true }
    }
    $false
}

function ConvertFrom-NetAccount {
    # Parses `net accounts` (English output). "Never", "None" and "Unlimited"
    # become 0. Returns nothing if the output is unreadable.
    param([object[]]$Text)
    $map = @{}
    foreach ($line in @($Text)) {
        if ("$line" -match '^(.+?):\s+(\S.*?)\s*$') { $map[$Matches[1].Trim()] = $Matches[2] }
    }
    if (-not $map.ContainsKey('Minimum password length')) { return }
    $num = { param($v) $n = 0; if ([int]::TryParse("$v", [ref]$n)) { $n } else { 0 } }
    [pscustomobject]@{
        MinLength        = & $num $map['Minimum password length']
        MaxAgeDays       = & $num $map['Maximum password age (days)']
        History          = & $num $map['Length of password history maintained']
        LockoutThreshold = & $num $map['Lockout threshold']
        LockoutMinutes   = & $num $map['Lockout duration (minutes)']
    }
}

function ConvertFrom-NetLocalGroup {
    # Member names from `net localgroup <group>` output: the lines between the
    # dashed rule and "The command completed".
    param([object[]]$Text)
    $inList = $false
    foreach ($line in @($Text)) {
        $s = "$line".Trim()
        if ($s -match '^-{10,}$') { $inList = $true; continue }
        if (-not $inList -or -not $s) { continue }
        if ($s -like 'The command completed*') { break }
        $s
    }
}

function ConvertTo-UsbStorageRecord {
    # Turns a USBSTOR model key and instance key into a device record.
    # Serials ending in &0 are real; a 2nd character of & means Windows made
    # one up because the device has no serial number.
    param([string]$ModelKey, [string]$InstanceKey, [string]$FriendlyName)
    $name = if ($FriendlyName) { $FriendlyName } else { $ModelKey }
    [pscustomobject]@{
        Device     = $name
        Kind       = ($ModelKey -split '&')[0]
        Serial     = $InstanceKey -replace '&\d+$', ''
        NoSerial   = ($InstanceKey.Length -gt 1 -and $InstanceKey.Substring(1, 1) -eq '&')
        InstanceId = $InstanceKey
    }
}

function Get-CommandPath {
    # The program path at the start of a command line such as
    #   "C:\Program Files\App\app.exe" /min   or   C:\Windows\x.exe -k netsvcs
    param([string]$Command, [string]$WindowsDir = $env:windir)
    $c = [Environment]::ExpandEnvironmentVariables("$Command").Trim()
    if (-not $c) { return '' }
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        $p = if ($end -gt 1) { $c.Substring(1, $end - 1) } else { $c.Trim('"') }
    } elseif ($c -match '^(.+?\.(exe|com|bat|cmd|scr|pif|vbs|vbe|js|jse|wsf|hta|dll|cpl|ps1|msi))(\s|,|$)') {
        $p = $Matches[1]
    } else {
        $p = ($c -split '\s+')[0]
    }
    if ($p.StartsWith('\??\')) { $p = $p.Substring(4) }
    if ($WindowsDir) {
        if ($p -match '^\\SystemRoot\\') { $p = $WindowsDir + $p.Substring(11) }
        if ($p -match '^(?i)system32\\') { $p = $WindowsDir + '\' + $p }
    }
    $p
}

function Get-SuspiciousReason {
    # Why a program path or command line looks like one of malware's usual
    # hiding places, or '' if nothing stands out.
    param([string]$Path, [string]$Command)
    $p = "$Path".ToLower()
    $c = "$Command".ToLower()
    $why = [System.Collections.Generic.List[string]]::new()
    if ($p -match '\\(temp|tmp)\\') { $why.Add('runs from a Temp folder') }
    if ($p -match '\\\$recycle\.bin\\|\\recycler\\|\\system volume information\\') { $why.Add('runs from the Recycle Bin or System Volume Information') }
    if ($p -match '\\appdata\\(roaming|local|locallow)\\[^\\]+\.(exe|scr|com|pif|dll|bat|cmd|vbs|js)$') { $why.Add('program sits directly in AppData') }
    if ($p -match '\\programdata\\[^\\]+\.(exe|scr|com|pif|dll|bat|cmd|vbs|js)$') { $why.Add('program sits directly in ProgramData') }
    if ($p -match '\\users\\public\\') { $why.Add('runs from the Public user folder') }
    if ($p -match '\.(jpg|jpeg|gif|png|bmp|pdf|doc|docx|xls|xlsx|txt|mp3|mp4|avi|zip)\.(exe|scr|com|pif|bat|cmd|vbs|js|lnk)$') { $why.Add('double file extension') }
    if ($p -match '\.(scr|pif)$') { $why.Add('screen saver or PIF file run as a program') }
    # A web address alone is common (browsers, updaters); it only counts when a script host fetches it.
    $scriptHost = '(^|[\\"\s])(powershell|pwsh|cmd|wscript|cscript|rundll32|bitsadmin|certutil|curl)(\.exe)?["\s]'
    if ($c -match 'mshta|regsvr32.+/i:' -or ($c -match 'https?://' -and $c -match $scriptHost)) { $why.Add('runs script or web content') }
    if ($c -match 'powershell|pwsh') {
        if ($c -match '\s-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}') { $why.Add('PowerShell with an encoded command') }
        elseif ($c -match '-w(indowstyle)?\s+h(idden)?\b' -and $c -match 'downloadstring|downloadfile|invoke-webrequest|iwr |iex|invoke-expression|frombase64string') {
            $why.Add('hidden PowerShell that downloads or runs code')
        }
    }
    $why -join '; '
}

function ConvertFrom-HostsFile {
    # Active lines of a hosts file as objects with Address and Name.
    param([string[]]$Text)
    foreach ($line in @($Text)) {
        $t = ("$line" -replace '#.*$', '').Trim()
        if (-not $t) { continue }
        $parts = @($t -split '\s+')
        for ($i = 1; $i -lt $parts.Count; $i++) {
            [pscustomobject]@{ Address = $parts[0]; Name = $parts[$i].ToLower() }
        }
    }
}

function Get-HostsHijack {
    # Hosts entries that point a security, update or search site somewhere.
    param($Entry)
    $security = '(microsoft|windowsupdate|windows\.com|virustotal|avast|avg|norton|symantec|mcafee|kaspersky|eset|malwarebytes|sophos|trendmicro|f-secure|bitdefender|clamav|avira|panda|comodo|google)'
    @($Entry | Where-Object { $_ -and $_.Name -match $security })
}

function ConvertFrom-AutorunInf {
    # The program an autorun.inf launches (open=, shellexecute= or a shell command), or ''.
    param([string[]]$Text)
    foreach ($line in @($Text)) {
        if ("$line" -match '^(?i)\s*(open|shellexecute|shell\\[^=]*\\command)\s*=\s*(.+)$') { return $Matches[2].Trim() }
    }
    ''
}

function New-ThreatRating {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Creates an object in memory; changes nothing on the system.')]
    param(
        [string]$Threat,
        [ValidateSet('Protected', 'Partly', 'Exposed', 'Unknown')][string]$Rating,
        [string]$Why,
        [string]$Fix,
        # Inherent = a limit no setting fully removes, or a low-risk default.
        # Reported as Info, so it does not hide the fixable items.
        [bool]$Inherent
    )
    [pscustomobject]@{ Threat = $Threat; Rating = $Rating; Why = $Why; Fix = $Fix; Inherent = $Inherent }
}

function ConvertTo-ThreatLevel {
    # Finding level for a threat rating.
    param([string]$Rating, [bool]$Inherent)
    switch ($Rating) {
        'Exposed' { if ($Inherent) { 'Info' } else { 'Risk' } }
        'Partly'  { if ($Inherent) { 'Info' } else { 'Warn' } }
        'Unknown' { 'Info' }
        default   { 'OK' }
    }
}

function Get-UpdateAgeRating {
    # Rates how long ago the last Windows update was installed.
    param([Nullable[datetime]]$LastUpdate, [datetime]$Now = (Get-Date))
    if ($null -eq $LastUpdate) {
        return [pscustomobject]@{ Days = $null; Level = 'Info'; Text = 'Could not read when Windows was last updated.' }
    }
    # Windows can report the install date a day ahead of local time; treat that as today.
    if ($LastUpdate -gt $Now) { $LastUpdate = $Now }
    $days = [int][math]::Floor(($Now - $LastUpdate).TotalDays)
    $level = if ($days -le 45) { 'OK' } elseif ($days -le 120) { 'Warn' } else { 'Risk' }
    [pscustomobject]@{
        Days  = $days
        Level = $level
        Text  = 'The last Windows update was installed {0} day(s) ago ({1:yyyy-MM-dd}).' -f $days, $LastUpdate
    }
}

function Format-WindowsBuild {
    # "Microsoft Windows 11 Pro, version 25H2, build 26200.7171"
    param([string]$Caption, [string]$DisplayVersion, [string]$Build, $Revision)
    $text = if ($Caption) { $Caption.Trim() } else { 'Windows' }
    if ($DisplayVersion) { $text += ", version $DisplayVersion" }
    if ($Build) {
        $text += ", build $Build"
        if ("$Revision" -ne '') { $text += ".$Revision" }
    }
    $text
}

# When each Windows 11 feature update stops getting security updates on Home and
# Pro editions. Source: Microsoft lifecycle page for Windows 11 Home and Pro
# (checked 2026-11-27). Enterprise and Education editions are serviced longer.
$script:Windows11Servicing = @{
    '21H2' = [datetime]'2023-10-10'
    '22H2' = [datetime]'2024-10-08'
    '23H2' = [datetime]'2025-11-11'
    '24H2' = [datetime]'2026-10-13'
    '25H2' = [datetime]'2027-10-12'
    '26H1' = [datetime]'2028-03-14'
    '26H2' = [datetime]'2028-10-09'
}

function Get-WindowsVersionSupport {
    # Whether this Windows 11 feature update still gets security updates.
    # Returns Level, Text and Fix, or nothing for systems it has no dates for.
    param([string]$Caption, [string]$DisplayVersion, [datetime]$Now = (Get-Date))
    if ($Caption -notmatch 'Windows 11' -or -not $DisplayVersion) { return }
    $version = $DisplayVersion.ToUpper()
    if (-not $script:Windows11Servicing.ContainsKey($version)) {
        return [pscustomobject]@{ Level = 'Info'; Fix = ''
            Text = "Windows 11 version $version is newer than this toolkit's support table, so its end-of-servicing date was not checked." }
    }
    $end = $script:Windows11Servicing[$version]
    $homeOrPro = $Caption -notmatch 'Enterprise|Education|IoT|LTSC'
    $fix = 'Settings > Windows Update: install the current feature update'
    if ($Now.Date -gt $end) {
        if ($homeOrPro) {
            return [pscustomobject]@{ Level = 'Risk'; Fix = $fix
                Text = "Windows 11 version $version stopped getting security updates on $($end.ToString('yyyy-MM-dd')) (Home and Pro editions)." }
        }
        return [pscustomobject]@{ Level = 'Info'; Fix = ''
            Text = "Windows 11 version $version ended servicing for Home and Pro on $($end.ToString('yyyy-MM-dd')). This edition is serviced longer; check Microsoft's lifecycle page for its date." }
    }
    $daysLeft = [int]($end - $Now.Date).TotalDays
    if ($homeOrPro -and $daysLeft -le 90) {
        return [pscustomobject]@{ Level = 'Warn'; Fix = $fix
            Text = "Windows 11 version $version stops getting security updates in $daysLeft day(s), on $($end.ToString('yyyy-MM-dd')) (Home and Pro editions)." }
    }
    [pscustomobject]@{ Level = 'OK'; Fix = ''
        Text = "Windows 11 version $version gets security updates until $($end.ToString('yyyy-MM-dd')) (Home and Pro editions)." }
}

function ConvertFrom-SecurityCenterState {
    # Decodes the productState number Security Center reports for an antivirus.
    param([long]$ProductState)
    $hex = '{0:X6}' -f $ProductState
    [pscustomobject]@{
        RealTime = $hex.Substring(2, 2) -in '10', '11'
        UpToDate = $hex.Substring(4, 2) -eq '00'
    }
}

#endregion

#region System readers

function Read-SharedTextFile {
    # Reads a text file that another program may hold open for writing (the
    # firewall log, the hosts file) by sharing read and write access.
    param([Parameter(Mandatory)][string]$Path)
    $fs = $null; $sr = $null
    try {
        $fs = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open,
                  [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $sr = [System.IO.StreamReader]::new($fs)
        while ($null -ne ($line = $sr.ReadLine())) { $line }
    } finally {
        if ($sr) { $sr.Dispose() }
        if ($fs) { $fs.Dispose() }
    }
}

function Get-FileSha256 {
    # SHA-256 of a file as lowercase hex, or '' if it cannot be read.
    param([string]$Path)
    try { (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() }
    catch { '' }
}

function Get-FileSigner {
    # 'Valid: <signer>' / 'NotSigned' / other Authenticode status, or '' if it cannot be read.
    param([string]$Path)
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate) {
            $name = if ($sig.SignerCertificate.Subject -match 'CN="?([^",]+)') { $Matches[1] } else { $sig.SignerCertificate.Subject }
            return "Valid: $name"
        }
        "$($sig.Status)"
    } catch { '' }
}

function Get-FileList {
    # Files under a folder (hidden ones too) with the given extensions, capped
    # so a huge Temp folder cannot stall the check.
    param([string]$Path, [string[]]$Extension, [switch]$Recurse, [int]$Max = 500)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return }
    $n = 0
    foreach ($f in (Get-ChildItem -LiteralPath $Path -File -Force -Recurse:$Recurse -ErrorAction SilentlyContinue)) {
        if ($Extension -and $f.Extension.ToLower() -notin $Extension) { continue }
        $f
        if (++$n -ge $Max) { break }
    }
}

function Get-ShortcutTarget {
    # Target of a .lnk file, or '' if it cannot be read.
    param([string]$Path)
    try { "$((New-Object -ComObject WScript.Shell).CreateShortcut($Path).TargetPath)" }
    catch { '' }
}

function Get-PasswordPolicy {
    # Local password and lockout policy from `net accounts`, or nothing.
    try { ConvertFrom-NetAccount -Text (& net.exe accounts 2>&1) }
    catch { Write-Verbose "net accounts failed: $($_.Exception.Message)" }
}

function Get-LocalAccount {
    # Local user accounts through CIM (works the same in every PowerShell 7
    # release; the LocalAccounts module does not load in some of them).
    try {
        Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount = TRUE' -ErrorAction Stop |
            ForEach-Object {
                [pscustomobject]@{
                    Name = "$($_.Name)"; SID = "$($_.SID)"; Enabled = -not $_.Disabled
                    PasswordRequired = [bool]$_.PasswordRequired; LockedOut = [bool]$_.Lockout
                }
            }
    } catch {
        Write-Verbose "Win32_UserAccount query failed: $($_.Exception.Message)"
    }
}

function Get-GuestAccount {
    # The built-in Guest account, found by its SID (ends in -501), so a renamed Guest is covered.
    Get-LocalAccount | Where-Object { $_.SID -match '^S-1-5-21-.+-501$' } | Select-Object -First 1
}

function Get-LocalAdminMember {
    # Members of the local Administrators group. The group is found by its SID
    # (S-1-5-32-544), so a renamed or non-English group name still works.
    # Returns nothing if `net localgroup` fails.
    $name = 'Administrators'
    try {
        $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
        $name = ($sid.Translate([System.Security.Principal.NTAccount]).Value -split '\\')[-1]
    } catch {
        Write-Verbose 'Could not translate the Administrators SID; using the English name.'
    }
    try { $out = @(& net.exe localgroup $name 2>&1) }
    catch { Write-Verbose "net localgroup failed: $($_.Exception.Message)"; return }
    if ($LASTEXITCODE -ne 0) { return }
    [pscustomobject]@{ Group = $name; Members = @(ConvertFrom-NetLocalGroup -Text $out) }
}

function Get-NetbtInterface {
    # NetBIOS setting of every TCP/IP interface (NetbiosOptions: 0 = from DHCP,
    # 1 = on, 2 = off). Reads the registry, so disabled and unplugged adapters
    # that would turn NetBIOS back on when reconnected are covered too.
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
    $names = @{}
    try {
        foreach ($c in @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop)) {
            if ($c.SettingID) { $names["$($c.SettingID)".ToUpper()] = $c.Description }
        }
    } catch {
        Write-Verbose "Win32_NetworkAdapterConfiguration query failed: $($_.Exception.Message)"
    }
    foreach ($leaf in @(Get-RegSubKeyName -Path $root)) {
        if ($leaf -notlike 'Tcpip_*') { continue }
        $guid = $leaf.Substring(6).ToUpper()
        $path = "$root\$leaf"
        $opt  = Get-RegValue -Path $path -Name 'NetbiosOptions'
        [pscustomobject]@{
            Path           = $path
            Description    = if ($names[$guid]) { $names[$guid] } else { "removed adapter $guid" }
            NetbiosOptions = if ($null -eq $opt) { 0 } else { [int]$opt }
        }
    }
}

function Get-ServiceInfo {
    # State and startup type of the named services; Installed = $false if absent.
    param([Parameter(Mandatory)][string[]]$Name)
    foreach ($n in $Name) {
        $s = $null
        try { $s = Get-CimInstance -ClassName Win32_Service -Filter "Name = '$n'" -ErrorAction Stop | Select-Object -First 1 }
        catch { Write-Verbose "Win32_Service query failed for ${n}: $($_.Exception.Message)" }
        if ($s) {
            [pscustomobject]@{ Name = $n; Installed = $true; DisplayName = "$($s.DisplayName)"; State = "$($s.State)"; StartMode = "$($s.StartMode)" }
        } else {
            [pscustomobject]@{ Name = $n; Installed = $false; DisplayName = $n; State = ''; StartMode = '' }
        }
    }
}

function Get-FirewallState {
    # Effective firewall state: service, profiles, and whether inbound Remote
    # Desktop / file sharing rules are enabled. $null fields mean "could not read".
    $state = [ordered]@{
        ServiceRunning = $null; Profiles = @(); AllOn = $null; AnyInboundAllow = $null
        AllLogBlocked = $null; RdpRuleOpen = $null; SmbRuleOpen = $null; Error = $null
    }
    try {
        $svc = Get-Service -Name mpssvc -ErrorAction Stop
        $state.ServiceRunning = ($svc.Status -eq 'Running')
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
        $state.Profiles = @($profiles | ForEach-Object {
            [pscustomobject]@{
                Name         = "$($_.Name)"
                Enabled      = "$($_.Enabled)" -eq 'True'
                InboundAllow = "$($_.DefaultInboundAction)" -eq 'Allow'
                LogBlocked   = "$($_.LogBlocked)" -eq 'True'
                LogFileName  = "$($_.LogFileName)"
            }
        })
        $state.AllOn           = $state.ServiceRunning -and -not @($state.Profiles | Where-Object { -not $_.Enabled }).Count
        $state.AnyInboundAllow = [bool]@($state.Profiles | Where-Object InboundAllow).Count
        $state.AllLogBlocked   = -not @($state.Profiles | Where-Object { -not $_.LogBlocked }).Count
        $open = { param($group)
            [bool]@(Get-NetFirewallRule -PolicyStore ActiveStore -DisplayGroup $group -ErrorAction SilentlyContinue |
                Where-Object { "$($_.Enabled)" -eq 'True' -and "$($_.Direction)" -eq 'Inbound' -and "$($_.Action)" -eq 'Allow' }).Count }
        $state.RdpRuleOpen = & $open 'Remote Desktop'
        $state.SmbRuleOpen = & $open 'File and Printer Sharing'
    } catch {
        $state.Error = $_.Exception.Message
    }
    [pscustomobject]$state
}

function Get-Smb1State {
    # $true / $false for the SMBv1 server protocol, or $null if it cannot be read.
    try {
        $cfg = Get-SmbServerConfiguration -ErrorAction Stop
        return [bool]$cfg.EnableSMB1Protocol
    } catch {
        $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1'
        if ($null -ne $v) { return ([int]$v -ne 0) }
        return $null
    }
}

function Get-LastUpdateDate {
    # When the most recent Windows update was installed, or $null.
    try {
        $dates = @(Get-HotFix -ErrorAction Stop | Where-Object InstalledOn | ForEach-Object { [datetime]$_.InstalledOn })
        if ($dates.Count) { return ($dates | Sort-Object -Descending | Select-Object -First 1) }
    } catch {
        Write-Verbose "Get-HotFix failed: $($_.Exception.Message)"
    }
    $null
}

function Get-WindowsBuild {
    # Edition, feature-update version (25H2), build and revision of this Windows.
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $os = Get-OsInfo
    [pscustomobject]@{
        Caption        = if ($os) { "$($os.Caption)" } else { "$(Get-RegValue -Path $key -Name 'ProductName')" }
        DisplayVersion = "$(Get-RegValue -Path $key -Name 'DisplayVersion')"
        Build          = "$(Get-RegValue -Path $key -Name 'CurrentBuild')"
        Revision       = "$(Get-RegValue -Path $key -Name 'UBR')"
    }
}

function Test-RestartPending {
    # True when installed updates are waiting for a restart to finish.
    Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
}

function Get-AntivirusStatus {
    # Antivirus products with real-time and definition status. Microsoft Defender
    # is read directly; other products come from Security Center.
    $list = [System.Collections.Generic.List[object]]::new()
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($mp.AntivirusEnabled -or $mp.RealTimeProtectionEnabled) {
            $age = if ($null -ne $mp.AntivirusSignatureAge) { [int]$mp.AntivirusSignatureAge } else { 0 }
            $list.Add([pscustomobject]@{
                Name = 'Microsoft Defender'; RealTime = [bool]$mp.RealTimeProtectionEnabled
                UpToDate = ($age -le 7); SignatureAgeDays = $age
            })
        }
    } catch {
        Write-Verbose "Get-MpComputerStatus failed: $($_.Exception.Message)"
    }
    try {
        foreach ($p in @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)) {
            if ("$($p.displayName)" -match 'Defender' -and $list.Count) { continue }
            $s = ConvertFrom-SecurityCenterState -ProductState ([long]$p.productState)
            $list.Add([pscustomobject]@{ Name = "$($p.displayName)"; RealTime = $s.RealTime; UpToDate = $s.UpToDate; SignatureAgeDays = $null })
        }
    } catch {
        Write-Verbose "Security Center query failed: $($_.Exception.Message)"
    }
    $list.ToArray()
}

function Get-ListeningTcpPort {
    # TCP ports listening on a network-facing address (not loopback).
    try {
        Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' } |
            ForEach-Object { [pscustomobject]@{ Address = "$($_.LocalAddress)"; Port = [int]$_.LocalPort; ProcessId = $_.OwningProcess } }
    } catch {
        Write-Verbose "Get-NetTCPConnection failed: $($_.Exception.Message)"
    }
}

function Get-OsInfo {
    # Windows edition, build and DEP policy, or nothing if CIM is unavailable.
    try { Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop | Select-Object -First 1 }
    catch { Write-Verbose "Win32_OperatingSystem query failed: $($_.Exception.Message)" }
}

#endregion

#region Readers for Find-MalwareIndicator

function Get-ServiceCommand {
    # Name and command line of every service.
    try {
        Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
            ForEach-Object { [pscustomobject]@{ Name = "$($_.Name)"; Command = "$($_.PathName)" } }
    } catch { Write-Verbose "Win32_Service query failed: $($_.Exception.Message)" }
}

function Get-RunningProgram {
    # Name, process ID and path of every running program whose path can be read.
    try {
        Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | Where-Object ExecutablePath |
            ForEach-Object { [pscustomobject]@{ Name = "$($_.Name)"; ProcessId = $_.ProcessId; Path = "$($_.ExecutablePath)" } }
    } catch { Write-Verbose "Win32_Process query failed: $($_.Exception.Message)" }
}

function Get-ScheduledTaskCommand {
    # Name and command line of every scheduled task action that runs a program.
    try {
        foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
            foreach ($a in @($t.Actions)) {
                if (-not $a -or -not $a.PSObject.Properties['Execute'] -or -not $a.Execute) { continue }
                [pscustomobject]@{
                    Name    = "$($t.TaskPath)$($t.TaskName)"
                    Execute = "$($a.Execute)"
                    Command = ("$($a.Execute) $($a.Arguments)").Trim()
                }
            }
        }
    } catch { Write-Verbose "Get-ScheduledTask failed: $($_.Exception.Message)" }
}

function Get-HostsEntry {
    # Active entries of this PC's hosts file.
    $path = "$env:windir\System32\drivers\etc\hosts"
    if (-not (Test-Path -LiteralPath $path)) { return }
    try { ConvertFrom-HostsFile -Text @(Read-SharedTextFile -Path $path) }
    catch { Write-Verbose "Could not read the hosts file: $($_.Exception.Message)" }
}

function Get-LocalDriveRoot {
    # Drive letters (C:) of fixed and removable drives.
    try {
        Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop |
            Where-Object { $_.DriveType -in 2, 3 } | ForEach-Object { "$($_.DeviceID)" }
    } catch { Write-Verbose "Win32_LogicalDisk query failed: $($_.Exception.Message)" }
}

function Get-DefenderExclusion {
    # Folders, files and processes Microsoft Defender is told not to scan.
    # Needs an Administrator window; returns nothing otherwise.
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        foreach ($kind in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension') {
            foreach ($v in @($pref.$kind)) {
                if ($v -and "$v" -notmatch '^N/A') { [pscustomobject]@{ Kind = $kind; Value = "$v" } }
            }
        }
    } catch { Write-Verbose "Get-MpPreference failed: $($_.Exception.Message)" }
}

function Test-BroadExclusion {
    # True for a Defender exclusion that hides a whole drive, a user profile,
    # a Temp or AppData folder, or every program of a kind.
    param([string]$Kind, [string]$Value)
    $v = "$Value".ToLower().TrimEnd('\')
    if ($Kind -eq 'ExclusionExtension') { return ($v.TrimStart('.') -in 'exe', 'dll', 'scr', 'bat', 'cmd', 'ps1', 'vbs', 'js') }
    if ($Kind -eq 'ExclusionProcess') { return ($v -match '(^|\\)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe$') }
    if ($v -match '^[a-z]:$') { return $true }
    if ($v -match '^[a-z]:\\users(\\[^\\]+)?$') { return $true }
    if ($v -match '\\(temp|tmp)$|\\appdata(\\(local|roaming|locallow))?$|\\downloads$|^[a-z]:\\programdata$|^[a-z]:\\windows$') { return $true }
    $false
}

#endregion

#region Router helpers

function ConvertFrom-SsdpResponse {
    # Server and Location headers of an SSDP reply.
    param([string]$Text)
    [pscustomobject]@{
        Server   = if ($Text -match '(?im)^SERVER:\s*(.+?)\s*$') { $Matches[1] } else { '' }
        Location = if ($Text -match '(?im)^LOCATION:\s*(.+?)\s*$') { $Matches[1] } else { '' }
    }
}

function Find-UpnpGateway {
    # Sends an SSDP M-SEARCH for an Internet Gateway Device and returns the
    # router's reply (Server and Location headers) if the given address
    # answers within the timeout, else nothing.
    param([Parameter(Mandatory)][string]$Router, [int]$TimeoutMs = 2500)
    $msg = "M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 2`r`n" +
           "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1`r`n`r`n"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($msg)
    $udp = $null
    try {
        $udp = [System.Net.Sockets.UdpClient]::new()
        $udp.Client.ReceiveTimeout = 500
        [void]$udp.Send($bytes, $bytes.Length, [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse('239.255.255.250'), 1900))
        [void]$udp.Send($bytes, $bytes.Length, [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($Router), 1900))
        $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
        while ((Get-Date) -lt $deadline) {
            $from = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            try { $data = $udp.Receive([ref]$from) } catch { continue }
            if ($from.Address.ToString() -ne $Router) { continue }
            return (ConvertFrom-SsdpResponse -Text ([System.Text.Encoding]::ASCII.GetString($data)))
        }
    } catch {
        Write-Verbose "UPnP discovery failed: $($_.Exception.Message)"
    } finally {
        if ($udp) { $udp.Close() }
    }
}

function Get-RouterFinding {
    # Findings for the router port results of Test-RouterExposure.
    param($Result, $Upnp, [switch]$UpnpChecked)
    $open = @($Result | Where-Object Open)
    foreach ($r in @($open | Where-Object Risk -eq 'High')) {
        New-Finding -Area Router -Level Risk -Message "Router port $($r.Port) ($($r.Service)) is open on the LAN." -Fix 'Turn it off in the router admin page (Administration / Services / WAN), or update the router firmware'
    }
    foreach ($r in @($open | Where-Object Risk -eq 'Review')) {
        New-Finding -Area Router -Level Info -Message "Router port $($r.Port) ($($r.Service)) is open. Fine if you use it."
    }
    $http  = [bool]@($open | Where-Object Port -eq 80).Count
    $https = [bool]@($open | Where-Object { $_.Port -in 443, 8443 }).Count
    if ($http -and -not $https) {
        New-Finding -Area Router -Level Warn -Message 'Router admin page is HTTP only, so its password crosses the network unencrypted.' -Fix 'Turn on HTTPS for the admin page (often under Administration > System) if the router supports it'
    }
    if (-not $open.Count) {
        New-Finding -Area Router -Level Info -Message 'No common TCP ports answered (the router may block this PC, or use other ports).'
    }
    if ($UpnpChecked) {
        if ($Upnp) {
            $detail = if ($Upnp.Server) { " ($($Upnp.Server))" } else { '' }
            New-Finding -Area Router -Level Warn -Message "The router answers UPnP discovery${detail}: any program on any device here can open ports to the internet without a password." -Fix 'Turn off UPnP in the router admin page unless a console or app really needs it'
        } else {
            New-Finding -Area Router -Level OK -Message 'The router did not answer UPnP discovery (off, or not reachable from this PC).'
        }
    }
}

#endregion
