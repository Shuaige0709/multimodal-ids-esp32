# Aggregate selected closed archives, then train a PC model. No firmware writes.
param(
    [string[]]$Captures = @("captures"),
    [Parameter(Mandatory=$true)][string]$FeaturesOut,
    [Parameter(Mandatory=$true)][string]$ModelOut,
    [ValidateSet("wireless", "multimodal")][string]$FeatureSet = "wireless",
    [int]$WindowMs = 100,
    [int]$LabelGuardMs = 1000,
    [string]$Python
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root
if (-not $Python) {
    $Python = Join-Path $Root ".venv-raw\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $Python)) { $Python = "python" }
}
& $Python -m host.train.raw_windows @Captures --out $FeaturesOut --window-ms $WindowMs --label-guard-ms $LabelGuardMs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Python -m host.train.train_raw --dataset $FeaturesOut --out $ModelOut --feature-set $FeatureSet
exit $LASTEXITCODE
