#!/usr/bin/env bash
# SYGNIF py — Desk launcher (Linux/macOS). Serves the chat + workflows web
# dashboard on http://127.0.0.1:8899 by default.
#
# Zero dependencies: the Desk is Python standard library only (http.server), so
# there is no venv and no pip install — it runs on the same Python 3.8+ as the seat.
#
# Env overrides:
#   SYGNIF_DESK_HOST   bind address (default 127.0.0.1)
#   SYGNIF_DESK_PORT   port         (default 8899)
#   SYGNIF_DESK_EXEC   set to 1 to let the model run local shell (default OFF)
#   OPENROUTER_API_KEY free OpenRouter key for the default provider
#   SYGNIF_PY_PYTHON   python interpreter to run with
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${SYGNIF_PY_PYTHON:-python3}"

if ! command -v "$PY" >/dev/null 2>&1; then
  echo "SYGNIF Desk needs Python 3.8+ but '$PY' was not found on PATH." >&2
  echo "Install Python 3, or set SYGNIF_PY_PYTHON to your interpreter." >&2
  exit 127
fi

export SYGNIF_DESK_HOST="${SYGNIF_DESK_HOST:-127.0.0.1}"
export SYGNIF_DESK_PORT="${SYGNIF_DESK_PORT:-8899}"

exec "$PY" "$HERE/desk.py" "$@"
