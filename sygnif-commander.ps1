# SYGNIF py — commander launcher (Windows PowerShell). Starts the hands hub.
# Mints and persists a bearer token to %USERPROFILE%\.sygnif\sygnif-py-commander.env
# on first run so the commander (which fails closed) has a token to run with.
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$py = $env:SYGNIF_PY_PYTHON
if (-not $py) {
    if (Get-Command python -ErrorAction SilentlyContinue) { $py = "python" }
    elseif (Get-Command py -ErrorAction SilentlyContinue) { $py = "py" }
}
if (-not $py) {
    Write-Error "SYGNIF py commander needs Python 3.8+ on PATH."
    exit 127
}

$envFile = $env:SYGNIF_PY_COMMANDER_ENV
if (-not $envFile) { $envFile = Join-Path $env:USERPROFILE ".sygnif\sygnif-py-commander.env" }
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $envFile) | Out-Null

if (-not $env:SYGNIF_PY_COMMANDER_TOKEN -and (Test-Path $envFile)) {
    $line = Get-Content $envFile | Where-Object { $_ -match "SYGNIF_PY_COMMANDER_TOKEN" } | Select-Object -First 1
    if ($line -match "=(.+)$") { $env:SYGNIF_PY_COMMANDER_TOKEN = $matches[1].Trim() }
}

if (-not $env:SYGNIF_PY_COMMANDER_TOKEN) {
    $tok = & $py -c "import secrets; print(secrets.token_hex(32))"
    $env:SYGNIF_PY_COMMANDER_TOKEN = $tok
    "SYGNIF_PY_COMMANDER_TOKEN=$tok" | Set-Content -Path $envFile -Encoding ASCII
    Write-Host "[sygnif-commander] minted a bearer token -> $envFile"
}

& $py (Join-Path $here "commander.py") @args
