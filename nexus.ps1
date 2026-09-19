# SYGNIF py — the Nexus (labeled agent portals).
#
#   nexus                 picker: table of live portals
#   nexus <type> [label]  attach-or-create a portal
#   nexus hub             3-pane command center
#   nexus serve           the web board on http://127.0.0.1:8910
#   nexus -h              full help
#
# Portals are tmux sessions, so on Windows run this inside WSL — tmux does not
# exist for native PowerShell. This wrapper exists so the launcher set is the
# same on every platform and gives a clear message instead of a stack trace.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$py = if ($env:SYGNIF_PY_PYTHON) { $env:SYGNIF_PY_PYTHON } else { 'python' }
if (-not (Get-Command $py -ErrorAction SilentlyContinue)) {
  Write-Error "SYGNIF Nexus needs Python 3.8+ but '$py' was not found on PATH."
  exit 127
}
if (-not (Get-Command tmux -ErrorAction SilentlyContinue)) {
  Write-Host "SYGNIF Nexus manages portals as tmux sessions, which native Windows does not have."
  Write-Host "Run it inside WSL:  wsl nexus"
  exit 127
}
& $py (Join-Path $here 'nexus.py') @args
