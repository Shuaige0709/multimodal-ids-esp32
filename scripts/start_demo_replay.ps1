param(
    [ValidateSet('Recovery','ArpOn','ArpOff','ArpTwoWay')][string]$Scene = 'Recovery',
    [int]$WebPort = 8080
)
$ErrorActionPreference='Stop'
$projectDir=Split-Path -Parent $PSScriptRoot
$scenes=@{
    Recovery=@('DEFENSE_On_Optional_20261118_113635.csv.log','2026-11-18T11:51:05',125)
    ArpOn=@('DEFENSE_On_Optional_20261118_113635.csv.log','2026-11-18T11:45:05',75)
    ArpOff=@('DEFENSE_Off_Optional_20261118_132554.csv.log','2026-11-18T13:28:30',75)
    ArpTwoWay=@('DEFENSE_On_Optional_20261118_113635.csv.log','2026-11-18T11:46:30',80)
}
$sceneData=$scenes[$Scene]
$logPath=Join-Path $projectDir ('data\raw\'+$sceneData[0])
if (-not (Test-Path -LiteralPath $logPath)) { throw "Existing recording not found: $logPath" }
$pythonPath=$null
foreach ($candidate in @((Join-Path $projectDir '.venv\Scripts\python.exe'),(Join-Path $env:USERPROFILE '.espressif\python_env\idf5.5_py3.11_env\Scripts\python.exe'))) {
    if (Test-Path -LiteralPath $candidate) {
        & $candidate -c 'import serial' 2>$null
        if ($LASTEXITCODE -eq 0) { $pythonPath=$candidate; break }
    }
}
if (-not $pythonPath) { throw 'Use the same Python environment with pyserial as the live collector.' }
Write-Host 'RECORDED DATA. Stop the live dashboard first if it uses the same port.'
Write-Host "PC: http://localhost:$WebPort"
try {
    Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.IPv4Address } | ForEach-Object {
        foreach ($address in $_.IPv4Address) { Write-Host ('Phone: http://{0}:{1}' -f $address.IPAddress,$WebPort) }
    }
} catch { Write-Host 'Phone: use the PC Wi-Fi IPv4 address and the same web port.' }
& $pythonPath (Join-Path $PSScriptRoot 'replay_demo_dashboard.py') --log $logPath --from $sceneData[1] --seconds $sceneData[2] --port $WebPort
exit $LASTEXITCODE
