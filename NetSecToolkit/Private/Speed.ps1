# Speed test helpers used by Test-NetworkSpeed. Not exported.

$script:SpeedTestBase = 'https://speed.cloudflare.com'

function Invoke-Transfer {
    # Downloads or uploads TotalBytes over Count parallel connections and returns the
    # measured throughput. Timing covers only the transfers, not runspace startup.
    param(
        [ValidateSet('Down', 'Up')][string]$Direction,
        [long]$TotalBytes,
        [int]$Count,
        [string]$BaseUri = $script:SpeedTestBase
    )
    $per = [long][math]::Ceiling($TotalBytes / $Count)
    $parts = 1..$Count | ForEach-Object -ThrottleLimit $Count -Parallel {
        $dir = $using:Direction; $per = $using:per; $base = $using:BaseUri
        $h = [System.Net.Http.HttpClient]::new(); $h.Timeout = [TimeSpan]::FromSeconds(90)
        $n = 0L; $start = 0L; $end = 0L
        try {
            if ($dir -eq 'Down') {
                $start = [System.Diagnostics.Stopwatch]::GetTimestamp()
                $resp = $h.GetAsync("$base/__down?bytes=$per",
                        [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
                $s = $resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $buf = [byte[]]::new(131072)
                while (($r = $s.Read($buf, 0, $buf.Length)) -gt 0) { $n += $r }
            } else {
                $content = [System.Net.Http.ByteArrayContent]::new([byte[]]::new($per))
                $start = [System.Diagnostics.Stopwatch]::GetTimestamp()
                $resp = $h.PostAsync("$base/__up", $content).GetAwaiter().GetResult()
                if ($resp.IsSuccessStatusCode) { $n = $per }
            }
            $end = [System.Diagnostics.Stopwatch]::GetTimestamp()
        } catch { } finally { $h.Dispose() }
        [pscustomobject]@{ Bytes = $n; Start = $start; End = $end }
    }
    $ok = @($parts | Where-Object Bytes -gt 0)
    if (-not $ok.Count) { return $null }
    $secs  = (($ok.End | Measure-Object -Maximum).Maximum - ($ok.Start | Measure-Object -Minimum).Minimum) /
             [System.Diagnostics.Stopwatch]::Frequency
    $bytes = ($ok.Bytes | Measure-Object -Sum).Sum
    [pscustomobject]@{
        Mbps    = [math]::Round($bytes * 8 / $secs / 1e6, 1)
        MB      = [math]::Round($bytes / 1MB, 1)
        Seconds = [math]::Round($secs, 1)
    }
}

function Get-TestSize {
    # Bytes needed for a test to run about $Seconds at the estimated speed, clamped to Min..Max.
    param([double]$Mbps, [long]$Min, [long]$Max, [int]$Seconds)
    [long][math]::Min($Max, [math]::Max($Min, $Mbps * 1e6 / 8 * $Seconds))
}

function Get-LatencyStat {
    # Median latency and jitter (average change between consecutive samples), in ms.
    param([double[]]$Samples)
    if (@($Samples).Count -lt 2) { return $null }
    $sorted = $Samples | Sort-Object
    $diffs  = for ($i = 1; $i -lt $Samples.Count; $i++) { [math]::Abs($Samples[$i] - $Samples[$i - 1]) }
    [pscustomobject]@{
        Median = [math]::Round($sorted[[int][math]::Floor($Samples.Count / 2)], 1)
        Jitter = [math]::Round(($diffs | Measure-Object -Average).Average, 1)
    }
}
