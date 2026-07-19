[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PidFile,

    [Parameter(Mandatory = $true)]
    [string]$StopFile,

    [Parameter(Mandatory = $true)]
    [string]$OutputFile,

    [ValidateRange(10, 1000)]
    [int]$PollMilliseconds = 25,

    [ValidateRange(1000, 120000)]
    [int]$MaximumDurationMilliseconds = 60000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$deadline = [DateTime]::UtcNow.AddMilliseconds($MaximumDurationMilliseconds)
$targetPid = $null
while ([DateTime]::UtcNow -lt $deadline -and $null -eq $targetPid) {
    if (Test-Path -LiteralPath $PidFile -PathType Leaf) {
        $text = (Get-Content -Raw -LiteralPath $PidFile).Trim()
        $parsed = 0
        if ([int]::TryParse($text, [ref]$parsed) -and $parsed -gt 0) {
            $targetPid = $parsed
            break
        }
    }
    if (Test-Path -LiteralPath $StopFile) {
        break
    }
    Start-Sleep -Milliseconds 10
}

$tcpCommand = Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue
$udpCommand = Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue
$pollCount = 0
$tcpObserved = $false
$udpObserved = $false
$tcpMaximumObserved = 0
$udpMaximumObserved = 0
$firstObservationUtc = $null
$observerErrors = 0

if ($null -ne $targetPid) {
    do {
        $pollCount += 1
        try {
            $tcpCount = if ($null -ne $tcpCommand) {
                @(Get-NetTCPConnection -OwningProcess $targetPid -ErrorAction SilentlyContinue).Count
            }
            else { 0 }
            $udpCount = if ($null -ne $udpCommand) {
                @(Get-NetUDPEndpoint -OwningProcess $targetPid -ErrorAction SilentlyContinue).Count
            }
            else { 0 }

            if ($tcpCount -gt 0 -or $udpCount -gt 0) {
                if ($null -eq $firstObservationUtc) {
                    $firstObservationUtc = [DateTime]::UtcNow.ToString('o')
                }
                if ($tcpCount -gt 0) { $tcpObserved = $true }
                if ($udpCount -gt 0) { $udpObserved = $true }
                if ($tcpCount -gt $tcpMaximumObserved) { $tcpMaximumObserved = $tcpCount }
                if ($udpCount -gt $udpMaximumObserved) { $udpMaximumObserved = $udpCount }
            }
        }
        catch {
            $observerErrors += 1
        }

        if (Test-Path -LiteralPath $StopFile) {
            break
        }
        Start-Sleep -Milliseconds $PollMilliseconds
    } while ([DateTime]::UtcNow -lt $deadline)
}

[ordered]@{
    observer = 'PowerShellNetTCPUDPPidPoll'
    target_pid_received = ($null -ne $targetPid)
    tcp_observer_available = ($null -ne $tcpCommand)
    udp_observer_available = ($null -ne $udpCommand)
    poll_interval_ms = $PollMilliseconds
    poll_count = $pollCount
    tcp_activity_observed = $tcpObserved
    udp_activity_observed = $udpObserved
    tcp_maximum_matching_rows = $tcpMaximumObserved
    udp_maximum_matching_rows = $udpMaximumObserved
    first_observation_utc = $firstObservationUtc
    observer_error_count = $observerErrors
    limitation = 'Polling observation can miss short-lived attempts and is not a network sandbox.'
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutputFile -Encoding UTF8
