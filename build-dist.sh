#!/usr/bin/env bash
# Build the distributable artifacts for SYGNIF py into ./dist :
#   sygnif-py.tar.gz   (Linux/macOS, fetched by install.sh)
#   sygnif-py.zip      (Windows, fetched by install.ps1)
#   install.sh, install.ps1  (copied alongside so a static host can serve them)
#
# Commit dist/ to the repo: the installers fetch these from
# https://raw.githubusercontent.com/Giansn/sygnif-py/main/dist by default, so the
# README one-liners just work. Override with SYGNIF_PY_BASE_URL for any static host.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

DIST="$HERE/dist"
rm -rf "$DIST"
mkdir -p "$DIST"

# Files that make up the runtime package (NOT the installers or dist tooling).
PKG=(
  seat.py pix.py render.py pentest.py tools.py models.py identity.py config.json
  centre.py commander.py desk.py nexus.py
  static/index.html static/app.js static/style.css static/theme-dark.css
  static/nexus.html
  sygnif.sh sygnif.ps1
  sygnif-centre.sh sygnif-centre.ps1
  sygnif-commander.sh sygnif-commander.ps1
  sygnif-desk.sh sygnif-desk.ps1
  sygnif-nexus.sh sygnif-nexus.ps1
  nexus.sh nexus.ps1
  README.md custom_tools.py.example methodology.md
)

for f in "${PKG[@]}"; do
  [ -f "$f" ] || { echo "missing package file: $f" >&2; exit 1; }
done

# Flat tarball: files at the archive root (static/ keeps its subdir), so
# install.sh extracts straight into HOME_DIR.
tar -czf "$DIST/sygnif-py.tar.gz" "${PKG[@]}"

# Zip for Windows — same layout (static/ subdir preserved).
if command -v zip >/dev/null 2>&1; then
  ( cd "$HERE" && zip -q "$DIST/sygnif-py.zip" "${PKG[@]}" )
else
  python3 - "$DIST/sygnif-py.zip" "${PKG[@]}" <<'PY'
import sys, zipfile
out, files = sys.argv[1], sys.argv[2:]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for f in files:
        z.write(f, f)
PY
fi

cp install.sh install.ps1 "$DIST/"

echo "built:"
ls -la "$DIST"
