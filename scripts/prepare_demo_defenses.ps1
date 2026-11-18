param(
    [ValidateSet('On','Off')][string]$Mode = 'On',
    [ValidateSet('Optional','Required')][string]$Pmf = 'Optional',
    [string]$Port = 'COM3',
    [switch]$FlashAndStart
)
$ErrorActionPreference = 'Stop'
$projectDir = Split-Path -Parent $PSScriptRoot
Push-Location $projectDir
try {
    & (Join-Path $PSScriptRoot 'configure_arp_guard.ps1') -Mode $Mode -Pmf $Pmf
    if (-not (Get-Command idf.py -ErrorAction SilentlyContinue)) {
        . C:\esp\v5.5.3\esp-idf\export.ps1
    }
    if (-not (Get-Command idf.py -ErrorAction SilentlyContinue)) { throw 'Open an ESP-IDF terminal first.' }
    & idf.py build
    if ($LASTEXITCODE -ne 0) { throw 'Build failed; firmware was not flashed.' }
    if ($FlashAndStart) {
        & idf.py -p $Port flash
        if ($LASTEXITCODE -ne 0) { throw 'Flash failed. Stop the UART collector/monitor and retry.' }
        & (Join-Path $PSScriptRoot 'start_demo_dashboard.ps1') -Port $Port -RunName "DEFENSE_${Mode}_${Pmf}"
    } else { Write-Host 'Build ready. Use -FlashAndStart to flash and open the dashboard.' }
} finally { Pop-Location }
