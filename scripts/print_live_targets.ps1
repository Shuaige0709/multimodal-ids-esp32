# print_live_targets.ps1
# Read data/live_state.json and print copy-paste exports for Kali attack scripts.
#
# Usage (from project root, PowerShell):
#   .\scripts\print_live_targets.ps1
#   .\scripts\print_live_targets.ps1 -Watch

param(
    [switch]$Watch,
    [int]$IntervalSec = 2
)

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Live = Join-Path $Root "data\live_state.json"

function Show-Targets {
    if (-not (Test-Path $Live)) {
        Write-Host "live_state.json not found: $Live"
        Write-Host "Start the collector first (session_windows.ps1 or nids_collector.py)"
        return $false
    }
    $s = Get-Content $Live -Raw -Encoding UTF8 | ConvertFrom-Json
    $ip = $s.esp32_ip
    $mac = $s.esp32_mac
    $labelHost = if ($env:NIDS_LABEL_HOST) { $env:NIDS_LABEL_HOST }
                 elseif ($s.label_host) { $s.label_host }
                 elseif ($s.collector_ip) { $s.collector_ip }
                 else { "192.168.220.1" }
    $labelPort = if ($env:NIDS_LABEL_PORT) { $env:NIDS_LABEL_PORT }
                 elseif ($s.control_port) { $s.control_port }
                 else { "9999" }
    $updated = $s.updated
    Write-Host ""
    Write-Host "=== live targets (updated $updated) ==="
    Write-Host "  ESP32 IP     : $ip"
    Write-Host "  ESP32 MAC    : $mac"
    Write-Host "  label_host   : $labelHost  (Kali START/STOP)"
    Write-Host "  collector_ip : $($s.collector_ip)  (ESP32 syslog path)"
    Write-Host ""
    Write-Host "If Kali can read this same live_state.json, you usually need NO exports."
    Write-Host "Otherwise paste:"
    Write-Host "----------------------------------------"
    if ($ip) { Write-Host "export NIDS_ESP32_IP=$ip" }
    if ($mac) { Write-Host "export NIDS_ESP32_MAC=$mac" }
    Write-Host "export NIDS_LABEL_HOST=$labelHost"
    Write-Host "export NIDS_LABEL_PORT=$labelPort"
    Write-Host "# optional: export NIDS_BSSID=.. NIDS_WIFI_IFACE=wlan0 NIDS_MON_IFACE=wlan0mon"
    Write-Host "sudo ./host/attacks/attack_deauth.sh"
    Write-Host "----------------------------------------"
    return $true
}

if ($Watch) {
    Write-Host "Watching $Live (Ctrl+C to stop)..."
    while ($true) {
        Clear-Host
        [void](Show-Targets)
        Start-Sleep -Seconds $IntervalSec
    }
} else {
    [void](Show-Targets)
}
