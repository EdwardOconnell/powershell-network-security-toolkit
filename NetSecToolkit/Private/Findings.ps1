# Findings: the shared result format of the audit commands (1.2.0).
# A finding has Area, Level (OK, Info, Warn, Risk), Message and an optional Fix.

$script:ToolkitVersion = '1.2.0'
$script:Copyright      = "Copyright Edward O'Connell III 2026"
$script:HardeningFix   = 'Set-HardeningBaseline'

# Findings from the last run of each audit command, keyed by command name.
# Invoke-NetSecAssistant reads these, so it can explain what was just run.
$script:LastRun = @{}

function Test-IsAdministrator {
    # True in an elevated window. Never throws (unlike Assert-Administrator).
    if (-not $IsWindows) { return $false }
    try {
        $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Verbose "Could not read the current Windows identity: $($_.Exception.Message)"
        return $false
    }
}

function Write-Finding {
    param(
        [ValidateSet('OK', 'Info', 'Warn', 'Risk')][string]$Level,
        [string]$Message,
        [string]$Fix
    )
    $colors = @{ OK = 'Green'; Info = 'Gray'; Warn = 'Yellow'; Risk = 'Red' }
    Write-Host ('  [{0,-4}] {1}' -f $Level, $Message) -ForegroundColor $colors[$Level]
    if ($Fix) { Write-Host ('         Fix: {0}' -f $Fix) -ForegroundColor DarkGray }
}

function New-Finding {
    # Prints a finding and returns it as an object.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Creates an object in memory; changes nothing on the system.')]
    param(
        [string]$Area,
        [ValidateSet('OK', 'Info', 'Warn', 'Risk')][string]$Level,
        [string]$Message,
        [string]$Fix,
        [switch]$Quiet
    )
    if (-not $Quiet) { Write-Finding -Level $Level -Message $Message -Fix $Fix }
    [pscustomobject]@{ Area = $Area; Level = $Level; Message = $Message; Fix = $Fix }
}

function Add-Finding {
    # Prints a finding and adds it to a list: Add-Finding $findings Firewall OK 'Firewall is on.'
    param(
        [Parameter(Mandatory, Position = 0)][AllowEmptyCollection()][System.Collections.IList]$List,
        [Parameter(Position = 1)][string]$Area,
        [Parameter(Position = 2)][ValidateSet('OK', 'Info', 'Warn', 'Risk')][string]$Level,
        [Parameter(Position = 3)][string]$Message,
        [Parameter(Position = 4)][string]$Fix
    )
    [void]$List.Add((New-Finding -Area $Area -Level $Level -Message $Message -Fix $Fix))
}

function Add-FindingRange {
    # Adds findings to a list, leaving out empty entries: Add-FindingRange $all $result.Findings
    param(
        [Parameter(Mandatory, Position = 0)][AllowEmptyCollection()][System.Collections.IList]$List,
        [Parameter(Position = 1)]$Finding
    )
    foreach ($f in @($Finding)) { if ($f) { [void]$List.Add($f) } }
}

function ConvertTo-WarningFinding {
    # Turns the plain warning strings of the 1.x commands into findings, so the
    # assistant and the HTML report can use them. No warnings = one OK finding.
    param([string]$Area, [string[]]$Warning, [string]$Fix, [string]$OkMessage)
    $list = @($Warning | Where-Object { $_ })
    if (-not $list.Count -and $OkMessage) {
        return (New-Finding -Area $Area -Level OK -Message $OkMessage -Quiet)
    }
    foreach ($w in $list) { New-Finding -Area $Area -Level Warn -Message $w -Fix $Fix -Quiet }
}

function Save-RunFinding {
    # Keeps the findings of an audit command for Invoke-NetSecAssistant.
    param([string]$Name, $Finding)
    $script:LastRun[$Name] = @($Finding | Where-Object { $_ })
}

function Get-FindingCount {
    # Counts per level, for summaries.
    param($Finding)
    $all = @($Finding | Where-Object { $_ })
    [pscustomobject]@{
        Risk  = @($all | Where-Object Level -eq 'Risk').Count
        Warn  = @($all | Where-Object Level -eq 'Warn').Count
        Info  = @($all | Where-Object Level -eq 'Info').Count
        OK    = @($all | Where-Object Level -eq 'OK').Count
        Total = $all.Count
    }
}

function Write-FindingSummary {
    # "N risk(s), N warning(s)." in green, yellow or red.
    param($Finding, [switch]$PointToAssistant)
    $c = Get-FindingCount $Finding
    $color = if ($c.Risk) { 'Red' } elseif ($c.Warn) { 'Yellow' } else { 'Green' }
    Write-Host ('  {0} risk(s), {1} warning(s).' -f $c.Risk, $c.Warn) -ForegroundColor $color
    if ($PointToAssistant -and ($c.Risk + $c.Warn)) {
        Write-Host '  Ask the assistant what to fix first: Invoke-NetSecAssistant (then type: plan)' -ForegroundColor DarkGray
    }
}

function Get-DefaultReportDir {
    # Documents\SecurityChecks, with a fallback if the shell folder is not set.
    $base = [Environment]::GetFolderPath('MyDocuments')
    if (-not $base) { $base = [System.IO.Path]::GetTempPath() }
    Join-Path $base 'SecurityChecks'
}

function Get-ConsoleWidth {
    $width = 120
    try {
        $w = $Host.UI.RawUI.BufferSize.Width
        if ($w -gt 40) { $width = $w - 1 }
    } catch {
        Write-Verbose 'No console buffer; using a width of 120.'
    }
    $width
}

function Write-Wrapped {
    # Prints text that fits the console: short lines as they are, long lines
    # word-wrapped with the same leading indent.
    param([string]$Text, [int]$Indent = 2, [string]$Color = 'Gray')
    $width = [math]::Max(30, [math]::Min(100, (Get-ConsoleWidth) - $Indent))
    $pad = ' ' * $Indent
    foreach ($para in ("$Text" -split "`r?`n")) {
        if ($para.Length -le $width) { Write-Host ($pad + $para) -ForegroundColor $Color; continue }
        $lead = if ($para -match '^(\s+)') { $Matches[1] } else { '' }
        $line = ''
        foreach ($word in ($para.Trim() -split '\s+')) {
            if (-not $line) { $line = $lead + $word }
            elseif (($line.Length + 1 + $word.Length) -le $width) { $line += ' ' + $word }
            else {
                Write-Host ($pad + $line) -ForegroundColor $Color
                $line = $lead + '   ' + $word
            }
        }
        if ($line) { Write-Host ($pad + $line) -ForegroundColor $Color }
    }
}

function ConvertTo-HtmlText {
    param([string]$Text)
    [System.Net.WebUtility]::HtmlEncode("$Text")
}

function Export-FindingHtml {
    # Writes findings as one self-contained HTML page (no scripts, no web requests).
    param($Finding, [string]$Path, [string]$Title, [string[]]$Note, [string[]]$Plan)
    $rank = @{ Risk = 0; Warn = 1; Info = 2; OK = 3 }
    $rows = @($Finding | Where-Object { $_ } | Sort-Object -Stable { $rank["$($_.Level)"] })
    $c = Get-FindingCount $rows
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.Append('<title>' + (ConvertTo-HtmlText $Title) + '</title><style>')
    [void]$sb.Append('body{font-family:Segoe UI,Tahoma,Arial,sans-serif;font-size:14px;margin:20px;color:#222;background:#fff}')
    [void]$sb.Append('h1{font-size:20px}h2{font-size:16px}table{border-collapse:collapse;width:100%}')
    [void]$sb.Append('th,td{border:1px solid #bbb;padding:5px 7px;text-align:left;vertical-align:top}th{background:#dde4ee}')
    [void]$sb.Append('tr.risk td{background:#f8d7d7}tr.warn td{background:#fff1c9}tr.ok td{background:#e6f4e6}')
    [void]$sb.Append('code{font-family:Consolas,monospace;font-size:13px}li{margin-bottom:6px}')
    [void]$sb.Append('</style></head><body><h1>' + (ConvertTo-HtmlText $Title) + '</h1>')
    [void]$sb.Append(('<p><b>{0} risk(s), {1} warning(s)</b>, {2} finding(s) in total.</p>' -f $c.Risk, $c.Warn, $c.Total))
    foreach ($n in @($Note)) { if ($n) { [void]$sb.Append('<p>' + (ConvertTo-HtmlText $n) + '</p>') } }
    if (@($Plan).Count) {
        [void]$sb.Append('<h2>What to fix first</h2><ol>')
        foreach ($step in @($Plan)) {
            $also = ''
            $body = "$step" -replace '^\d+\.\s*', ''
            if ($body -match "(?s)^(.*)`n\s*(Same fix for: .*)$") { $body = $Matches[1]; $also = $Matches[2] }
            $parts = $body -split "`n\s*Fix:\s*", 2
            $item = ConvertTo-HtmlText $parts[0]
            if ($parts.Count -gt 1) { $item += '<br>Fix: <code>' + (ConvertTo-HtmlText $parts[1]) + '</code>' }
            if ($also) { $item += '<br>' + (ConvertTo-HtmlText $also) }
            [void]$sb.Append('<li>' + $item + '</li>')
        }
        [void]$sb.Append('</ol>')
    }
    [void]$sb.Append('<table><tr><th>Level</th><th>Area</th><th>Finding</th><th>Fix</th></tr>')
    foreach ($f in $rows) {
        [void]$sb.Append(('<tr class="{0}"><td>{1}</td><td>{2}</td><td>{3}</td><td><code>{4}</code></td></tr>' -f
            "$($f.Level)".ToLower(), (ConvertTo-HtmlText $f.Level), (ConvertTo-HtmlText $f.Area),
            (ConvertTo-HtmlText $f.Message), (ConvertTo-HtmlText $f.Fix)))
    }
    [void]$sb.Append('</table><p>Generated by NetSecToolkit ' + $script:ToolkitVersion + '. ' +
        (ConvertTo-HtmlText $script:Copyright) + '</p></body></html>')
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))
}
