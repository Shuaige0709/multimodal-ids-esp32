param(
    [Parameter(Mandatory=$true)][ValidateSet('On','Off')][string]$Mode,
    [string]$GatewayIP,
    [string]$GatewayMac,
    [string]$Bssid,
    [ValidateSet('Optional','Required')][string]$Pmf = 'Optional'
)
$ErrorActionPreference = 'Stop'
$profilePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'main\arp_guard_profile.h'
$existing = if (Test-Path -LiteralPath $profilePath) { Get-Content -LiteralPath $profilePath -Raw } else { '' }
function Resolve-Value([string]$value, [string]$macro) {
    if ($value) { return $value }
    $match = [regex]::Match($existing, '#define\s+' + $macro + '\s+"([^"\r\n]+)"')
    if ($match.Success) { return $match.Groups[1].Value }
    throw "Missing $macro. First provide -GatewayIP, -GatewayMac and the ESP32's -Bssid from a trusted, attack-free setup."
}
$GatewayIP = Resolve-Value $GatewayIP 'ARP_GUARD_GATEWAY_IP'
$GatewayMac = (Resolve-Value $GatewayMac 'ARP_GUARD_GATEWAY_MAC').Replace('-',':').ToUpperInvariant()
$Bssid = (Resolve-Value $Bssid 'ARP_GUARD_BSSID').Replace('-',':').ToUpperInvariant()
$address = $null
if (-not [System.Net.IPAddress]::TryParse($GatewayIP, [ref]$address) -or $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or $GatewayIP -eq '0.0.0.0') { throw 'GatewayIP must be a nonzero IPv4 address.' }
foreach ($mac in @($GatewayMac,$Bssid)) {
    if ($mac -notmatch '^([0-9A-F]{2}:){5}[0-9A-F]{2}$' -or $mac -eq '00:00:00:00:00:00' -or ([Convert]::ToInt32($mac.Substring(0,2),16) -band 1)) { throw 'MAC/BSSID must be a nonzero unicast MAC address.' }
}
$enabled = if ($Mode -eq 'On') { 1 } else { 0 }
$pmfRequired = if ($Pmf -eq 'Required') { 1 } else { 0 }
$content = @"
#pragma once
/* Local trust profile: verify against the router before attack. */
#define ARP_GUARD_ENABLE $enabled
#define ARP_GUARD_GATEWAY_IP "$GatewayIP"
#define ARP_GUARD_GATEWAY_MAC "$GatewayMac"
#define ARP_GUARD_BSSID "$Bssid"
#define WIFI_TRUSTED_AP_ENABLE $enabled
#define WIFI_PMF_REQUIRED $pmfRequired
"@
[System.IO.File]::WriteAllText($profilePath,$content,[System.Text.UTF8Encoding]::new($false))
Write-Host "ARP defense: $Mode"
Write-Host "Trusted gateway: $GatewayIP -> $GatewayMac"
Write-Host "Trusted ESP32 AP BSSID: $Bssid"
Write-Host "Trusted AP binding: $Mode; PMF policy: $Pmf"
if ($Pmf -eq 'Required') { Write-Warning 'PMF Required refuses APs without PMF. Enable PMF on the router first.' }
Write-Host 'Now run idf.py build, stop UART collector, then idf.py -p COM3 flash.'
