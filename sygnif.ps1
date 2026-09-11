# SYGNIF py launcher (Windows PowerShell). Runs the seat from its install dir.
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$py = $env:SYGNIF_PY_PYTHON
if (-not $py) {
    if (Get-Command python -ErrorAction SilentlyContinue) { $py = "python" }
    elseif (Get-Command py -ErrorAction SilentlyContinue) { $py = "py" }
}
if (-not $py) {
    Write-Error "SYGNIF py needs Python 3.8+ on PATH. Install it from https://python.org or the Microsoft Store."
    exit 127
}

& $py (Join-Path $here "seat.py") @args
