# SYGNIF py — one-line installer for Windows PowerShell.
#
#   irm https://<host>/install.ps1 | iex
#
# Downloads the SYGNIF py package, unpacks it to %USERPROFILE%\.sygnif-py
# (override with $env:SYGNIF_PY_HOME), and drops a `sygnif.cmd` launcher into a
# WindowsApps-style bin dir on PATH.
#
# Env knobs:
#   SYGNIF_PY_BASE_URL  where to fetch sygnif-py.zip from (default below)
#   SYGNIF_PY_HOME      install dir (default: ~\.sygnif-py)
#   SYGNIF_PY_BIN       launcher dir (default: ~\.sygnif-bin)

$ErrorActionPreference = "Stop"

$baseUrl = if ($env:SYGNIF_PY_BASE_URL) { $env:SYGNIF_PY_BASE_URL } else { "https://raw.githubusercontent.com/Giansn/sygnif-py/main/dist" }
$homeDir = if ($env:SYGNIF_PY_HOME) { $env:SYGNIF_PY_HOME } else { Join-Path $HOME ".sygnif-py" }
$binDir  = if ($env:SYGNIF_PY_BIN)  { $env:SYGNIF_PY_BIN }  else { Join-Path $HOME ".sygnif-bin" }
$zip     = "sygnif-py.zip"

function Say($m) { Write-Host "[sygnif-py] $m" -ForegroundColor Cyan }
function Die($m) { Write-Host "[sygnif-py] $m" -ForegroundColor Red; exit 1 }

# --- prerequisites ----------------------------------------------------------
$py = $null
foreach ($c in @("python", "py")) {
    if (Get-Command $c -ErrorAction SilentlyContinue) { $py = $c; break }
}
if (-not $py) { Die "Python 3.8+ is required. Install from https://python.org or the Microsoft Store, then re-run." }

# --- download + unpack ------------------------------------------------------
Say "installing to $homeDir (from $baseUrl)"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("sygnif-py-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
    $target = Join-Path $tmp $zip
    Say "downloading $zip ..."
    Invoke-WebRequest -Uri "$baseUrl/$zip" -OutFile $target -UseBasicParsing
    if (-not (Test-Path $target) -or (Get-Item $target).Length -eq 0) { Die "download failed or empty: $baseUrl/$zip" }

    New-Item -ItemType Directory -Force -Path $homeDir | Out-Null
    Expand-Archive -Path $target -DestinationPath $homeDir -Force
    if (-not (Test-Path (Join-Path $homeDir "seat.py"))) { Die "package looks incomplete (no seat.py in $homeDir)." }
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

# --- launchers on PATH ------------------------------------------------------
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
# The seat, the Desk (dashboard), the Centre (knot point), and the commander
# (hands) each get a .cmd.
foreach ($pair in @(
    @("sygnif", "sygnif.ps1"),
    @("sygnif-desk", "sygnif-desk.ps1"),
    @("sygnif-nexus", "sygnif-nexus.ps1"),
    @("sygnif-centre", "sygnif-centre.ps1"),
    @("sygnif-commander", "sygnif-commander.ps1")
)) {
    $launcher = Join-Path $binDir ($pair[0] + ".cmd")
    "@echo off`r`npowershell -NoProfile -ExecutionPolicy Bypass -File `"$homeDir\$($pair[1])`" %*" |
        Set-Content -Path $launcher -Encoding ASCII
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$binDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$binDir", "User")
    Say "added $binDir to your user PATH (open a new terminal to pick it up)."
}

Say "installed. commands: sygnif (seat), sygnif-desk (browser dashboard), sygnif-nexus (portal board, needs WSL), sygnif-centre (knot point), sygnif-commander (hands)"
Say "default model is a FREE OpenRouter slug — make a free key at openrouter.ai, then:"
Say '        $env:OPENROUTER_API_KEY = "sk-or-..."'
Say "to use your own Claude Pro/Max subscription instead:  sygnif login   (needs the claude CLI)"
Say "add other models in $homeDir\config.json or ~\.sygnif\sygnif-py.json"
