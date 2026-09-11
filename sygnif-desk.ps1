# SYGNIF py — Desk launcher (Windows PowerShell). Serves the chat + workflows
# web dashboard on http://127.0.0.1:8899 by default.
#
# Zero dependencies: the Desk is Python standard library only (http.server), so
# there is no venv and no pip install — it runs on the same Python 3.8+ as the seat.
#
# Env overrides: SYGNIF_DESK_HOST, SYGNIF_DESK_PORT, SYGNIF_DESK_EXEC (1=allow
# local shell, default off), OPENROUTER_API_KEY, SYGNIF_PY_PYTHON.
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$py = $env:SYGNIF_PY_PYTHON
if (-not $py) {
    if (Get-Command python -ErrorAction SilentlyContinue) { $py = "python" }
    elseif (Get-Command py -ErrorAction SilentlyContinue) { $py = "py" }
}
if (-not $py) {
    Write-Error "SYGNIF Desk needs Python 3.8+ on PATH. Install it from https://python.org or the Microsoft Store."
    exit 127
}

if (-not $env:SYGNIF_DESK_HOST) { $env:SYGNIF_DESK_HOST = "127.0.0.1" }
if (-not $env:SYGNIF_DESK_PORT) { $env:SYGNIF_DESK_PORT = "8899" }

& $py (Join-Path $here "desk.py") @args
