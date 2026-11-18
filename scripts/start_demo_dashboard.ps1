param(
    [string]$Port = 'COM3',
    [int]$WebPort = 8080,
    [int]$LabelPort = 10000,
    [ValidatePattern('^[A-Za-z0-9_\-]*$')][string]$RunName = '',
    [ValidateSet('zh','en')][string]$Language = 'zh',
    [switch]$OpenBrowser
)
$ErrorActionPreference = 'Stop'
$projectDir = Split-Path -Parent $PSScriptRoot
$candidates = @(
    (Join-Path $projectDir '.venv\Scripts\python.exe'),
    (Join-Path $env:USERPROFILE '.espressif\python_env\idf5.5_py3.11_env\Scripts\python.exe')
)
$pythonPath = $null
foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate) {
        try {
            & $candidate -c 'import serial' 2>$null
            if ($LASTEXITCODE -eq 0) { $pythonPath = $candidate; break }
        } catch { continue }
    }
}
if (-not $pythonPath) {
    throw 'No Python environment with pyserial found. Install it using .\.venv\Scripts\python.exe -m pip install pyserial'
}
Write-Host "PC: http://localhost:$WebPort"
try {
    Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.IPv4Address } | ForEach-Object {
        foreach ($address in $_.IPv4Address) {
            Write-Host ('Phone ({0}): http://{1}:{2}' -f $_.InterfaceAlias, $address.IPAddress, $WebPort)
        }
    }
} catch { Write-Host 'Use ipconfig to find the PC Wi-Fi IPv4 address.' }
Write-Host 'Keep this window open. Stop other UART collectors/monitors first. Ctrl+C to stop.'
$collectorArgs = @((Join-Path $PSScriptRoot 'serial_collector.py'), '--port', $Port, '--standby', '--web', '--web-port', $WebPort)
$collectorArgs += @('--language', $Language)
$collectorArgs += @('--label-port', $LabelPort)
if ($OpenBrowser) { $collectorArgs += '--open-browser' }
if ($RunName) {
    $outPath = Join-Path $projectDir ('data\raw\' + $RunName + '_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.csv')
    $collectorArgs += @('--out', $outPath)
}
& $pythonPath @collectorArgs
exit $LASTEXITCODE
