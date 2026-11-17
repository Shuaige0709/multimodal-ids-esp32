param([int]$WebPort=8080, [string]$LabelHost='')
$ErrorActionPreference='Stop'
$status=Invoke-RestMethod "http://localhost:$WebPort/api/status"
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
Write-Output "sudo -E ./host/attacks/arp_guard_test.sh"
