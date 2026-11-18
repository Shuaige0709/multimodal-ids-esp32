param(
    [string]$Profile = '',
    [switch]$UseExistingFirmware,
    [switch]$DryRun
)
$ErrorActionPreference='Stop'
$projectDir=Split-Path -Parent $PSScriptRoot
if (-not $Profile) { $Profile=Join-Path $projectDir 'demo\competition\network.json' }
$config=Get-Content -LiteralPath $Profile -Raw | ConvertFrom-Json
foreach ($field in @('esp32_ip','gateway_ip','windows_hostonly_ip')) {
    $address=$null
    if (-not [System.Net.IPAddress]::TryParse($config.$field,[ref]$address) -or $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { throw "Invalid IPv4 in $field" }
}
Write-Host ('Live demo: SSID {0}, ESP32 IP from live USB data, AP {1}, channel {2}' -f $config.ssid,$config.ap_bssid,$config.channel)
Write-Host 'Firmware policy: ARP protection On, trusted AP binding On, PMF Optional.'
Write-Host 'Close the old collector/monitor before continuing. USB stays connected.'
if ($DryRun) {
    Write-Host ('Plan: configure trusted gateway; {0}; open English live dashboard on {1}; COM {2}.' -f $(if ($UseExistingFirmware) {'use existing firmware'} else {'build and flash'}),$config.dashboard_port,$config.serial_port)
    Write-Host 'No device, file or network settings changed.'
    return
}
# Refuse before configuration or flashing: an old replay must never remain
# behind the URL used by the live dashboard and Kali readiness checks.
$portProbe = [System.Net.Sockets.TcpClient]::new()
try {
    $pending = $portProbe.BeginConnect('127.0.0.1', [int]$config.dashboard_port, $null, $null)
    if ($pending.AsyncWaitHandle.WaitOne(1000)) {
        try { $portProbe.EndConnect($pending) } catch { }
    }
    $occupied = $portProbe.Connected
} finally { $portProbe.Dispose() }
if ($occupied) {
    $source = 'an existing service'
    try {
        $status = Invoke-RestMethod -Uri ('http://127.0.0.1:{0}/api/status' -f $config.dashboard_port) -TimeoutSec 2
        if ($status.presentation.mode -eq 'recorded') {
            $source = 'recorded playback: ' + $status.presentation.source
        } elseif ($null -ne $status.serial) { $source = 'an existing dashboard' }
    } catch { }
    throw ('Port {0} is occupied by {1}. Stop its terminal with Ctrl+C, then retry. No firmware changes were made.' -f $config.dashboard_port,$source)
}
Push-Location $projectDir
try {
    if (-not $UseExistingFirmware) {
        & (Join-Path $PSScriptRoot 'configure_arp_guard.ps1') -Mode On -Pmf Optional -GatewayIP $config.gateway_ip -GatewayMac $config.gateway_mac -Bssid $config.ap_bssid
        if (-not (Get-Command idf.py -ErrorAction SilentlyContinue)) { . C:\esp\v5.5.3\esp-idf\export.ps1 }
        & idf.py build
        if ($LASTEXITCODE -ne 0) { throw 'Build failed; demo has not started.' }
        & idf.py -p $config.serial_port flash
        if ($LASTEXITCODE -ne 0) { throw 'Flash failed; stop the old serial reader and retry.' }
    }
    Write-Host 'Kali: sudo python3 host/attacks/competition_demo.py'
    Write-Host 'Leave this terminal open for the live USB feed. Ctrl+C saves and closes it.'
    & (Join-Path $PSScriptRoot 'start_demo_dashboard.ps1') -Port $config.serial_port -WebPort $config.dashboard_port -LabelPort $config.serial_label_port -RunName COMPETITION_LIVE -Language en -OpenBrowser
} finally { Pop-Location }
