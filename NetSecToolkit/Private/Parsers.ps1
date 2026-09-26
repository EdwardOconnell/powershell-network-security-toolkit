# Pure parsing functions: no system calls, so they're easy to unit test.

function Get-RiskyPortMatch {
    # Returns "port/service" for each commonly attacked port covered by the given
    # firewall LocalPort values (single ports or ranges like 137-139).
    param([string[]]$Ports, [hashtable]$RiskyPorts = $script:RiskyPorts)
    foreach ($p in $Ports) {
        if ($p -match '^\d+$') {
            if ($RiskyPorts.ContainsKey([int]$p)) { "$p/$($RiskyPorts[[int]$p])" }
        }
        elseif ($p -match '^(\d+)-(\d+)$') {
            $lo = [int]$Matches[1]; $hi = [int]$Matches[2]
            foreach ($k in ($RiskyPorts.Keys | Sort-Object)) {
                if ($k -ge $lo -and $k -le $hi) { "$k/$($RiskyPorts[$k])" }
            }
        }
    }
}

function ConvertFrom-NetshWlanInterface {
    # Parses `netsh wlan show interfaces` output into one hashtable per interface.
    # Handles Wi-Fi 7 multi-link (MLO) "LinkID:" lines, which go into a _links list.
    param([string[]]$Text)
    $blocks = [System.Collections.Generic.List[hashtable]]::new()
    $cur = $null
    foreach ($raw in $Text) {
        $line = "$raw".TrimEnd("`r")
        if ($line -match '^\s*Name\s*:\s(.+)$') {
            $cur = @{ Name = $Matches[1].Trim() }; $blocks.Add($cur); continue
        }
        if (-not $cur) { continue }
        if ($line -match 'LinkID:\s*(\d+).*?AP:\s*([0-9a-fA-F:]+).*?RSSI:\s*(-?\d+).*?Channel:\s*(\d+).*?Band:\s*([\d.]+\s*GHz).*?BW:\s*(\d+)') {
            if (-not $cur.ContainsKey('_links')) { $cur['_links'] = [System.Collections.Generic.List[object]]::new() }
            $cur['_links'].Add([pscustomobject]@{
                Id = [int]$Matches[1]; AP = $Matches[2]; Rssi = [int]$Matches[3]
                Channel = [int]$Matches[4]; Band = $Matches[5]; Width = [int]$Matches[6]
            })
            continue
        }
        if ($line -match '^\s+(\S.*?)\s*:\s(.*)$') {
            $k = $Matches[1].Trim(); $v = $Matches[2].Trim()
            if (-not $v) { continue }
            if ($cur.ContainsKey($k) -and $cur[$k] -ne $v) { $cur[$k] = "$($cur[$k]) + $v" }
            elseif (-not $cur.ContainsKey($k)) { $cur[$k] = $v }
        }
    }
    $blocks.ToArray()
}

function ConvertFrom-FirewallLogLine {
    # Parses one pfirewall.log line into an object. Returns nothing for headers,
    # blank lines, or malformed lines.
    param([string]$Line)
    if ([string]::IsNullOrWhiteSpace($Line) -or $Line.StartsWith('#')) { return }
    $f = $Line -split ' '
    if ($f.Count -lt 8) { return }
    $t = [datetime]::MinValue
    if (-not [datetime]::TryParseExact("$($f[0]) $($f[1])", 'yyyy-MM-dd HH:mm:ss',
             [System.Globalization.CultureInfo]::InvariantCulture,
             [System.Globalization.DateTimeStyles]::None, [ref]$t)) { return }
    [pscustomobject]@{
        Time        = $t
        Action      = $f[2]
        Protocol    = $f[3]
        Source      = $f[4]
        Destination = $f[5]
        SourcePort  = $f[6]
        DestPort    = $f[7]
    }
}

function Get-ServiceRiskNote {
    # Advice for an exposed router service, based on its risk level.
    param([bool]$Open, [ValidateSet('High', 'Review', 'Expected')][string]$Risk)
    if (-not $Open) { return '' }
    switch ($Risk) {
        'High'   { 'TURN OFF unless you really need it' }
        'Review' { 'OK if you use it; otherwise disable' }
        default  { 'Normal' }
    }
}
