param([int]$WebPort=8080, [string]$LabelHost='', [switch]$FullDemo, [switch]$PmfOnly, [switch]$CheckPmf)
$ErrorActionPreference='Stop'
if (([int]$FullDemo.IsPresent + [int]$PmfOnly.IsPresent + [int]$CheckPmf.IsPresent) -gt 1) { throw 'Choose only one campaign or check.' }
if ($CheckPmf) {
    $profile=Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'main\arp_guard_profile.h') -Raw
    $match=[regex]::Match($profile, '#define\s+ARP_GUARD_BSSID\s+"((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})"')
    if (-not $match.Success) { throw 'No valid trusted BSSID in the local profile.' }
    Write-Output ("sudo -E bash ./host/attacks/check_ap_pmf.sh --bssid '" + $match.Groups[1].Value + "'")
    return
}
$status=Invoke-RestMethod "http://localhost:$WebPort/api/status"
if ($PmfOnly -and ($status.protection.wireless.pmf -ne 'required' -or -not $status.protection.wireless_fresh -or -not $status.wifi_fresh -or $status.wifi -ne 'up')) { throw 'PMF test requires fresh, connected Required-mode firmware. Do not run it while still disconnected or in Optional mode.' }
if ($PmfOnly -and $status.protection.communication -notin @('reachable','recovered')) { throw 'Wait for a successful gateway communication baseline before starting the PMF attacks.' }
if (-not $status.protection.fresh -or -not $status.protection.device_ip) { throw 'No fresh trusted-network device IP. Start the new firmware and dashboard first.' }
$target=$status.protection.device_ip
$gateway=$status.protection.target
if (-not $gateway) { throw 'Waiting for the first gateway probe; try again in a few seconds.' }
Write-Host 'Copy the following lines into Kali:'
if (-not $LabelHost) {
    $adapter = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { $_.Name -like '*VMnet1*' } | Select-Object -First 1
    if ($adapter) {
        $LabelHost = ($adapter.GetIPProperties().UnicastAddresses | Where-Object { $_.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -First 1).Address.IPAddressToString
    }
}
if ($LabelHost) {
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($LabelHost,[ref]$parsed)) { throw 'LabelHost must be an IP address.' }
    Write-Output "export NIDS_LABEL_HOST='$LabelHost'"
    Write-Output "export NIDS_SERIAL_LABEL_HOST='$LabelHost'"
}
Write-Output "export NIDS_ESP32_IP='$target'"
Write-Output "export NIDS_GATEWAY_IP='$gateway'"
Write-Output "export NIDS_ARP_DURATION='60'"
if ($FullDemo -or $PmfOnly) {
    $bssid=$status.protection.wireless.bssid
    $mac=$status.latest.host_mac
    $channel=$status.latest.channel
    if (-not $status.protection.wireless_fresh -or $bssid -notmatch '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$' -or $mac -notmatch '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$' -or $channel -notmatch '^([1-9]|1[0-3])$') { throw 'Wait for fresh device MAC, AP BSSID and channel before generating the campaign.' }
    Write-Output "export NIDS_ESP32_MAC='$mac'"
    Write-Output "export NIDS_BSSID='$bssid'"
    Write-Output "export NIDS_WIFI_CHANNEL='$channel'"
    if ($PmfOnly) { Write-Output 'sudo -E bash ./host/attacks/demo_acceptance.sh --pmf-only' }
    else { Write-Output 'sudo -E bash ./host/attacks/demo_acceptance.sh' }
} else { Write-Output "sudo -E ./host/attacks/arp_guard_test.sh" }
