$ErrorActionPreference = "Stop"

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw "Go 1.21 or newer is required."
}

$goos = (& go env GOOS).Trim()
$extension = switch ($goos) {
    "windows" { "dll" }
    "darwin" { "dylib" }
    default { "so" }
}

New-Item -ItemType Directory -Path "dist" -Force | Out-Null
& go test ./... -count=1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$env:CGO_ENABLED = "1"
& go build -buildvcs=false -buildmode=c-shared -o "dist/hk-grok-inspection.$extension" .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Built dist/hk-grok-inspection.$extension"
