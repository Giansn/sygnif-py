#!/usr/bin/env bash
# SYGNIF py — Nexus launcher (Linux/macOS). Serves the portal board — your
# tmux agent sessions, spawnable/renamable/killable from the browser — on
# http://127.0.0.1:8910 by default.
#
# Zero pip dependencies: the Nexus is Python standard library only, but it
# manages portals AS tmux sessions, so tmux must be installed.
#
# Env overrides:
#   SYGNIF_NEXUS_BIND  bind address (default 127.0.0.1)
#   SYGNIF_NEXUS_PORT  port         (default 8910)
#   SYGNIF_NEXUS_TYPES extra portal types, "name=command,name2=command2"
#   SYGNIF_PY_PYTHON   python interpreter to run with
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${SYGNIF_PY_PYTHON:-python3}"

if ! command -v "$PY" >/dev/null 2>&1; then
  echo "SYGNIF Nexus needs Python 3.8+ but '$PY' was not found on PATH." >&2
  echo "Install Python 3, or set SYGNIF_PY_PYTHON to your interpreter." >&2
  exit 127
fi

if ! command -v tmux >/dev/null 2>&1; then
  echo "SYGNIF Nexus needs tmux (portals are tmux sessions)." >&2
  echo "Install it: apt/dnf/brew install tmux" >&2
  exit 127
fi

# No args = the web board (what `sygnif-nexus` has always meant). The full
# terminal control plane lives on the `nexus` launcher.
if [ "$#" -eq 0 ]; then exec "$PY" "$HERE/nexus.py" serve; fi
exec "$PY" "$HERE/nexus.py" "$@"
