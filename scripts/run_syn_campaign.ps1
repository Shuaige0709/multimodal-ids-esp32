# Explicitly authorized isolated-lab runs only. Does not start VirtualBox or change firewall/sudo.
param(
    [string]$KaliHost = '192.168.56.101',
    [string]$KaliUser = 'hao',
    [string]$KaliProject = '/home/hao/桌面/multimodal-ids-esp32',
    [string]$LabelHost = '192.168.56.1',
    [string]$Ssid = '5F23',
    [string]$Port = 'COM3',
    [string]$Python,
    [string]$Out,
    [switch]$Run
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $Python) { $Python = 'python' }
$PythonCommand = Get-Command $Python -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $PythonCommand) { throw "Python not found: $Python. Add Python to PATH or specify -Python." }
$Python = $PythonCommand.Source
$CampaignArgs = @('-u', "$Root/scripts/syn_campaign.py", '--kali-host', $KaliHost,
    '--kali-user', $KaliUser, '--kali-project', $KaliProject, '--label-host', $LabelHost,
    '--ssid', $Ssid, '--port', $Port)
if ($Out) { $CampaignArgs += @('--out', $Out) }
if ($Run) { $CampaignArgs += '--run' }
& $Python @CampaignArgs
exit $LASTEXITCODE
