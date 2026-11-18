$ErrorActionPreference='Stop'
Push-Location $PSScriptRoot
try {
    foreach ($pass in 1..2) {
        & xelatex -interaction=nonstopmode -halt-on-error competition_demo.tex
        if ($LASTEXITCODE -ne 0) { throw 'Slide compilation failed.' }
    }
} finally { Pop-Location }
