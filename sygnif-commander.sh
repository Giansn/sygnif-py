#!/usr/bin/env bash
# SYGNIF py — commander launcher (Linux/macOS). Starts the hands (exec/fs) hub.
#
# The commander FAILS CLOSED without a bearer token. This launcher mints one on
# first run and persists it to ~/.sygnif/sygnif-py-commander.env (chmod 600), so
# the same token is reused across restarts. Point a seat at the commander by
# sourcing that file (or exporting SYGNIF_PY_COMMANDER_TOKEN) before `sygnif`.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${SYGNIF_PY_PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "SYGNIF py commander needs Python 3.8+ but '$PY' was not found on PATH." >&2
  exit 127
fi

ENV_FILE="${SYGNIF_PY_COMMANDER_ENV:-$HOME/.sygnif/sygnif-py-commander.env}"
mkdir -p "$(dirname "$ENV_FILE")"

if [ -z "${SYGNIF_PY_COMMANDER_TOKEN:-}" ]; then
  if [ -f "$ENV_FILE" ]; then
    # shellcheck disable=SC1090
    . "$ENV_FILE"
  fi
fi

if [ -z "${SYGNIF_PY_COMMANDER_TOKEN:-}" ]; then
  if command -v openssl >/dev/null 2>&1; then
    TOK="$(openssl rand -hex 32)"
  else
    TOK="$("$PY" -c 'import secrets; print(secrets.token_hex(32))')"
  fi
  export SYGNIF_PY_COMMANDER_TOKEN="$TOK"
  umask 077
  printf 'export SYGNIF_PY_COMMANDER_TOKEN=%s\n' "$TOK" > "$ENV_FILE"
  chmod 600 "$ENV_FILE" 2>/dev/null || true
  echo "[sygnif-commander] minted a bearer token -> $ENV_FILE"
  echo "[sygnif-commander] to let a seat use the commander:  . $ENV_FILE"
fi

exec "$PY" "$HERE/commander.py" "$@"
