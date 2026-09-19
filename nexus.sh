#!/usr/bin/env bash
# SYGNIF py — the Nexus (terminal + web control plane for labeled agent portals).
#
#   nexus                 picker: table of live portals
#   nexus <type> [label]  attach-or-create a portal
#   nexus hub             3-pane command center
#   nexus serve           the web board on http://127.0.0.1:8910
#   nexus -h              full help
#
# Portals ARE tmux sessions, so tmux must be installed. Python stdlib only.
#
# Env overrides:
#   SYGNIF_NEXUS_BIND / SYGNIF_NEXUS_PORT   web board bind + port
#   SYGNIF_NEXUS_TYPES  extra portal types, "name=command,name2=command2"
#   SYGNIF_NEXUS_STATE  where recents/hub state live (default ~/.sygnif)
#   SYGNIF_PY_PYTHON    python interpreter to run with
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
  echo "Install it: apt/dnf/pkg/brew install tmux" >&2
  exit 127
fi

exec "$PY" "$HERE/nexus.py" "$@"
