#!/usr/bin/env bash
# SYGNIF py — Centre launcher (Linux/macOS). Starts the knot-point hub.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${SYGNIF_PY_PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "SYGNIF py Centre needs Python 3.8+ but '$PY' was not found on PATH." >&2
  exit 127
fi

exec "$PY" "$HERE/centre.py" "$@"
