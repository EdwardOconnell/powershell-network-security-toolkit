# Shared helpers used by the public commands. Not exported.

# Ports commonly abused when exposed inbound
$script:RiskyPorts = @{
    21 = 'FTP'; 22 = 'SSH'; 23 = 'Telnet'; 135 = 'RPC'
    137 = 'NetBIOS'; 138 = 'NetBIOS'; 139 = 'NetBIOS'; 445 = 'SMB'
    1433 = 'SQL Server'; 3389 = 'RDP'; 5900 = 'VNC'
    5985 = 'WinRM'; 5986 = 'WinRM-HTTPS'
}

function Assert-Windows {
    if (-not $IsWindows) { throw 'This command uses Windows-only cmdlets.' }
}

function Assert-Administrator {
    Assert-Windows
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This command needs an elevated PowerShell window (Run as Administrator).'
    }
}

function Write-Section([string]$Title) { Write-Host "`n=== $Title ===" -ForegroundColor Cyan }

function Show-Table {
    # Renders objects as a table on the host, in order with Write-Host output.
    param([Parameter(ValueFromPipeline)]$InputObject, [switch]$Wrap)
    begin   { $items = [System.Collections.Generic.List[object]]::new() }
    process { if ($null -ne $InputObject) { $items.Add($InputObject) } }
    end {
        if ($items.Count) { $items | Format-Table -AutoSize -Wrap:$Wrap | Out-String -Width 220 | Write-Host }
        else              { Write-Host "  (none)`n" }
    }
}

function ConvertTo-UInt32 {
    # 192.168.1.10 -> 3232235786
    param([Parameter(Mandatory)][string]$IPAddress)
    $b = ([System.Net.IPAddress]::Parse($IPAddress)).GetAddressBytes()
    [Array]::Reverse($b)
    [BitConverter]::ToUInt32($b, 0)
}

function ConvertTo-IPAddressString {
    # 3232235786 -> 192.168.1.10
    param([Parameter(Mandatory)][uint32]$Value)
    $b = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($b)
    ([System.Net.IPAddress]::new($b)).ToString()
}

function Get-SubnetRange {
    # Usable host range for an IPv4 address/prefix. Large subnets are narrowed
    # to the /24 around the address so a scan stays quick.
    param(
        [Parameter(Mandatory)][string]$IPAddress,
        [Parameter(Mandatory)][ValidateRange(1, 30)][int]$PrefixLength,
        [int]$MaxHosts = 1024
    )
    $ipNum     = ConvertTo-UInt32 $IPAddress
    $mask      = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $PrefixLength))
    $network   = [uint32]($ipNum -band $mask)
    $hostCount = [math]::Pow(2, 32 - $PrefixLength) - 2
    $narrowed  = $false
    if ($hostCount -gt $MaxHosts) {
        $network = [uint32]($ipNum -band [uint32]4294967040)   # 255.255.255.0
        $PrefixLength = 24; $hostCount = 254; $narrowed = $true
    }
    [pscustomobject]@{
        Network   = ConvertTo-IPAddressString $network
        Prefix    = $PrefixLength
        Cidr      = "$(ConvertTo-IPAddressString $network)/$PrefixLength"
        First     = [uint32]($network + 1)
        Last      = [uint32]($network + $hostCount)
        HostCount = [int]$hostCount
        Narrowed  = $narrowed
    }
}

function Test-RandomizedMac {
    # Locally administered MACs (2nd hex digit 2, 6, A or E) are usually
    # phones and laptops using Wi-Fi privacy addresses.
    param([string]$MacAddress)
    if (-not $MacAddress -or $MacAddress.Length -lt 2) { return $false }
    $MacAddress.Substring(1, 1) -match '[26AEae]'
}

function Test-DeviceDisabled {
    # True for devices turned off on purpose in Device Manager
    param($Device)
    "$($Device.Problem)" -in 'CM_PROB_DISABLED', '22'
}

function Get-ActiveInterfaceAlias {
    # The connected adapter with the best default route (the one carrying internet traffic)
    $upIdx = @(Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -ExpandProperty ifIndex)
    (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { $_.ifIndex -in $upIdx } |
        Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias
}
