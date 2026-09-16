# Raw USB collector launcher; no firmware flash unless explicitly requested.
param(
    [ValidateSet("raw", "legacy")][string]$Mode = "raw",
    [string]$Port = "COM3",
    [int]$Baud = 921600,
    [string]$Out,
    [string]$Label,
    [int]$LabelPort = 0,
    [string]$LabelBind = "127.0.0.1",
    [string]$LabelAdvertise,
    [string]$Esp32Ip,
    [int]$WaitEsp32 = 60,
    [string]$Python,
    [switch]$Flash
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root
if (-not $Python) {
    $LocalPython = Join-Path $Root ".venv-raw\Scripts\python.exe"
    $Python = if (Test-Path -LiteralPath $LocalPython) { $LocalPython } else { "python" }
}
if ($Flash) {
    if (-not (Get-Command idf.py -ErrorAction SilentlyContinue)) {
        throw "Open an ESP-IDF terminal to flash. Do not start monitor during raw capture."
    }
    idf.py -p $Port build flash
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
if ($Mode -eq "legacy") {
    & $Python "$Root\scripts\bringup.py" --mode legacy --wait-esp32 $WaitEsp32
} else {
    $CollectorArgs = @("$Root\scripts\bringup.py", "--mode", "raw", "--port", $Port,
                       "--baud", "$Baud", "--standby", "--label-port", "$LabelPort",
                       "--label-bind", $LabelBind)
    if ($Out) { $CollectorArgs += @("--out", $Out) }
    if ($Label) { $CollectorArgs += @("--label", $Label) }
    if ($LabelAdvertise) { $CollectorArgs += @("--label-advertise", $LabelAdvertise) }
    if ($Esp32Ip) { $CollectorArgs += @("--esp32-ip", $Esp32Ip) }
    & $Python @CollectorArgs
}
exit $LASTEXITCODE
