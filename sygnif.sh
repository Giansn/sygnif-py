#!/usr/bin/env bash
# SYGNIF py launcher (Linux/macOS). Runs the seat from wherever it is installed.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PY="${SYGNIF_PY_PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "SYGNIF py needs Python 3.8+ but '$PY' was not found on PATH." >&2
  echo "Install Python 3, or set SYGNIF_PY_PYTHON to your interpreter." >&2
  exit 127
fi

exec "$PY" "$HERE/seat.py" "$@"
