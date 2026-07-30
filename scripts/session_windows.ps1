# session_windows.ps1
# One-shot "start a lab session" on the Windows host.
# Does NOT build firmware every time — only collector + print Kali exports.
#
# Usage (from project root):
#   .\scripts\session_windows.ps1
#   .\scripts\session_windows.ps1 -WaitEsp32 90
#   .\scripts\session_windows.ps1 -Flash     # also remind / optionally flash if idf.py in PATH

param(
    [int]$WaitEsp32 = 60,
    [switch]$Flash
)

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

Write-Host "============================================================"
Write-Host " NIDS lab session (Windows host)"
Write-Host "============================================================"
Write-Host " Project : $Root"
Write-Host ""
Write-Host " You only need this when collecting / attacking, not every"
Write-Host " time you open the folder to edit code."
Write-Host ""
Write-Host " Checklist:"
Write-Host "  [1] Phone hotspot / AP SSID matches main/net_config.h"
Write-Host "  [2] ESP32 flashed (skip if firmware unchanged)"
Write-Host "  [3] This PC joined to the same Wi-Fi"
Write-Host "  [4] Collector running -> then copy exports to Kali"
Write-Host "============================================================"
Write-Host ""

if ($Flash) {
    if (Get-Command idf.py -ErrorAction SilentlyContinue) {
        Write-Host "Running: idf.py build flash"
        idf.py build flash
    } else {
        Write-Host "idf.py not in PATH. Open an ESP-IDF PowerShell and run:"
        Write-Host "  cd `"$Root`""
        Write-Host "  idf.py build flash monitor"
        Write-Host ""
    }
} else {
    Write-Host "Firmware: not flashing (pass -Flash to try, or use ESP-IDF shell)."
    Write-Host ""
}

Write-Host "Starting collector via bringup.py (Ctrl+C stops)..."
Write-Host "When ESP32 appears, run in another PowerShell:"
Write-Host "  .\scripts\print_live_targets.ps1"
Write-Host "and paste the export lines into Kali."
Write-Host ""

python "$Root\scripts\bringup.py" --wait-esp32 $WaitEsp32
