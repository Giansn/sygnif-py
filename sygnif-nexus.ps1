# SYGNIF py — Nexus launcher (Windows PowerShell).
#
# The Nexus manages portals as tmux sessions, and tmux does not run natively on
# Windows. Run the Nexus inside WSL instead:
#
#   wsl -e sh -c "~/.sygnif-py/sygnif-nexus.sh"
#
# (Install sygnif-py inside WSL first with the Linux one-liner from the README.)
$ErrorActionPreference = "Stop"

if (Get-Command wsl -ErrorAction SilentlyContinue) {
    Write-Host "SYGNIF Nexus needs tmux, which is Linux/macOS only. Launching via WSL..."
    wsl -e sh -c 'test -x "$HOME/.sygnif-py/sygnif-nexus.sh" && exec "$HOME/.sygnif-py/sygnif-nexus.sh" || { echo "sygnif-py is not installed inside WSL — run the Linux install one-liner there first (see README)."; exit 1; }'
} else {
    Write-Error "SYGNIF Nexus needs tmux (Linux/macOS). On Windows, install WSL, then install sygnif-py inside it and run sygnif-nexus there."
    exit 1
}
