function Invoke-NetSecAssistant {
    <#
    .SYNOPSIS
        Security assistant: explains findings, answers questions and says what to fix first.
    .DESCRIPTION
        Loads the findings from the checks you ran this session (or from the pipeline,
        or runs a scan with -Scan) and answers questions about them.

        Offline mode (default) uses notes built into the module; nothing leaves the PC.
        Claude mode sends the question and the findings to the Claude API. It needs your
        own API key in the ANTHROPIC_API_KEY environment variable; the key is read from
        there for each request and is never saved, shown or logged by the toolkit.
        MAC addresses, this PC's name and the user name are masked first unless
        -NoRedact is given. API usage is billed to your Anthropic account.

        With no -Question it opens an interactive prompt (NetSec-AI). Type help there
        for the commands. The alias nsai runs this command.
    .PARAMETER Question
        Ask one question (or a command such as plan or summary) and return.
    .PARAMETER InputObject
        Findings from a check's -PassThru output.
    .PARAMETER Mode
        Offline or Claude. Default: Offline, or the NETSEC_ASSISTANT_MODE environment variable.
    .PARAMETER Model
        Claude model for Claude mode. Default: the NETSEC_CLAUDE_MODEL environment
        variable, else claude-sonnet-5-5.
    .PARAMETER Scan
        Run Get-HardeningStatus and Get-AccountAudit first.
    .PARAMETER NoRedact
        Send MAC addresses, the PC name and the user name to Claude as they are.
    .PARAMETER PassThru
        With -Question, also return the answer text.
    .EXAMPLE
        Invoke-NetSecAssistant -Scan
    .EXAMPLE
        Get-HardeningStatus -PassThru | Invoke-NetSecAssistant -Question plan
    .EXAMPLE
        nsai "what is netbios"
    .EXAMPLE
        Invoke-NetSecAssistant -Mode Claude
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$Question,
        [Parameter(ValueFromPipeline)][object[]]$InputObject,
        [ValidateSet('Offline', 'Claude')][string]$Mode,
        [string]$Model,
        [switch]$Scan,
        [switch]$NoRedact,
        [switch]$PassThru
    )
    begin { $piped = [System.Collections.Generic.List[object]]::new() }
    process {
        foreach ($o in @($InputObject)) {
            if (-not $o) { continue }
            if ($o.PSObject.Properties['Findings']) { foreach ($f in @($o.Findings)) { if ($f) { $piped.Add($f) } } }
            elseif ($o.PSObject.Properties['Level'] -and $o.PSObject.Properties['Message']) { $piped.Add($o) }
        }
    }
    end {
        if (-not $Mode) { $Mode = if ($env:NETSEC_ASSISTANT_MODE -eq 'Claude') { 'Claude' } else { 'Offline' } }
        if (-not $Model) { $Model = if ($env:NETSEC_CLAUDE_MODEL) { $env:NETSEC_CLAUDE_MODEL } else { $script:ClaudeDefaultModel } }
        if ($Mode -eq 'Claude' -and -not (Test-ClaudeKeyPresent)) {
            Write-Finding -Level Warn -Message 'Claude mode needs your API key in the ANTHROPIC_API_KEY environment variable of this window. Using offline mode.'
            $Mode = 'Offline'
        }
        $state = @{ Mode = $Mode; Model = $Model; Findings = @(); Sources = @(); History = @(); NoRedact = [bool]$NoRedact }

        if ($Scan) { Invoke-AssistantScan $state }
        elseif ($piped.Count) { $state.Findings = $piped.ToArray(); $state.Sources = @('pipeline') }
        else { Import-LastRunFinding $state }

        if ($Question) {
            $answer = Invoke-AssistantTurn -State $state -Line $Question
            if ($PassThru) { $answer }
            return
        }

        Write-Section 'NetSecToolkit assistant'
        if ($state.Mode -eq 'Claude') {
            Write-Host "  Mode: Claude ($Model)"
            if (-not $NoRedact) { Write-Host "  MAC addresses, this PC's name and your user name are masked before sending." -ForegroundColor DarkGray }
        } else {
            Write-Host '  Mode: offline (built-in notes; nothing leaves this PC)'
        }
        Write-Host ''
        Write-Wrapped -Text (Get-AssistantSummary $state) -Indent 2 -Color White
        Write-Host ''
        Write-Host '  Ask a question, or type: scan, summary, plan, list, explain <n>, topics, help, exit' -ForegroundColor DarkGray

        while ($true) {
            Write-Host ''
            $line = Read-Host 'NetSec-AI'
            if ($null -eq $line) { break }
            $line = "$line".Trim()
            if (-not $line) { continue }
            if ($line -match '^(exit|quit|q|bye)$') { break }
            Write-Host ''
            $null = Invoke-AssistantTurn -State $state -Line $line
        }
    }
}
