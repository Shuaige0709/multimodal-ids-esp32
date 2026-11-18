$ErrorActionPreference='Stop'
Push-Location $PSScriptRoot
try {
    $marp=Join-Path $PSScriptRoot 'tooling\node_modules\.bin\marp.cmd'
    if (-not (Test-Path -LiteralPath $marp)) {
        & npm --prefix (Join-Path $PSScriptRoot 'tooling') ci --ignore-scripts --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw 'Marp installation failed.' }
    }
    & $marp --html --allow-local-files competition_demo.md -o competition_demo.pdf
    if ($LASTEXITCODE -ne 0) { throw 'PDF export failed.' }
    & $marp --html competition_demo.md -o competition_demo.html
    if ($LASTEXITCODE -ne 0) { throw 'HTML export failed.' }
} finally { Pop-Location }
