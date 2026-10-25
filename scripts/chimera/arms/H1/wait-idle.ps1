# Waits until the guest is idle before a snapshot is committed, and reports what ran meanwhile.
#
# Installers leave Windows work queued (Start-menu and search indexing, Update Orchestrator,
# EdgeUpdate, background tasks). A snapshot committed before that work has run replays it in
# every analysis: on H3 (committed a minute after install-apps.ps1) the scans saw 9
# backgroundTaskHost starts during al-khaser, which then reported nt_yield_execution 5/5
# (H2c: 0/5). Idle here means $Quiet consecutive 30 s windows in which other processes used
# under $MaxCpu CPU seconds and none started.
param(
    [int]$Quiet = 4,
    [double]$MaxCpu = 1.0,
    [int]$TimeoutMinutes = 20
)
$seen = @{}; Get-CimInstance Win32_Process | ForEach-Object { $seen["$($_.ProcessId)"] = 1 }
$cpu = @{}; Get-Process | ForEach-Object { $cpu["$($_.Id)"] = $_.TotalProcessorTime.TotalSeconds }
$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$streak = 0
while ($streak -lt $Quiet) {
    if ((Get-Date) -gt $deadline) { "not idle after $TimeoutMinutes minutes"; exit 1 }
    Start-Sleep -Seconds 30
    $busy = 0
    Get-Process | Where-Object Id -ne $PID | ForEach-Object {
        $prev = $cpu["$($_.Id)"]; if ($null -eq $prev) { $prev = 0 }
        $busy += $_.TotalProcessorTime.TotalSeconds - $prev
        $cpu["$($_.Id)"] = $_.TotalProcessorTime.TotalSeconds
    }
    $new = @(Get-CimInstance Win32_Process | Where-Object { -not $seen.ContainsKey("$($_.ProcessId)") })
    $new | ForEach-Object { $seen["$($_.ProcessId)"] = 1 }
    $names = ($new | ForEach-Object {
        $n = $_.Name; if ($_.CommandLine -match '-ServerName:(\S+)') { $n += "[$($Matches[1])]" }; $n }) -join ', '
    if ($busy -lt $MaxCpu -and $new.Count -eq 0) { $streak++ } else { $streak = 0 }
    "{0} busy_cpu_s={1,5:N1} quiet={2}/{3} new: {4}" -f (Get-Date -Format HH:mm:ss), $busy, $streak, $Quiet, $names
}
"idle"
exit 0
