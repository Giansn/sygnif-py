# SYGNIF py — Centre launcher (Windows PowerShell). Starts the knot-point hub.
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$py = $env:SYGNIF_PY_PYTHON
if (-not $py) {
    if (Get-Command python -ErrorAction SilentlyContinue) { $py = "python" }
    elseif (Get-Command py -ErrorAction SilentlyContinue) { $py = "py" }
}
if (-not $py) {
    Write-Error "SYGNIF py Centre needs Python 3.8+ on PATH."
    exit 127
}

& $py (Join-Path $here "centre.py") @args
