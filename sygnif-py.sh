#!/usr/bin/env bash
# sygnif-py — launch the SYGNIF py seat in a persistent tmux session.
#
# Usage:  sygnif-py [model] [session]
#   model    a model key from config.json          (default: glm)
#   session  tmux session name                      (default: the model name)
#
# Sources ~/.sygnif/<model>.env if present (e.g. ~/.sygnif/glm.env) so the
# model's API key lands in the seat's environment. Runs the seat inside tmux so
# it survives a disconnect or the screen sleeping — detach with Ctrl-b then d,
# and run sygnif-py again to reattach the same session. Falls back to a direct
# run when tmux is not installed.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${SYGNIF_PY_PYTHON:-python3}"
MODEL="${1:-glm}"
SESS="${2:-$MODEL}"

# The seat's own command: source the model's env file (deferred $HOME so it is
# read at launch time), then exec the seat on that model.
RUN="set -a; [ -f \$HOME/.sygnif/${MODEL}.env ] && . \$HOME/.sygnif/${MODEL}.env; set +a; exec ${PY} ${HERE}/seat.py --model ${MODEL}"

if [ -n "${TMUX:-}" ]; then exec bash -lc "$RUN"; fi          # already in tmux
if command -v tmux >/dev/null 2>&1; then
  if tmux has-session -t "$SESS" 2>/dev/null; then exec tmux attach -t "$SESS"; fi
  exec tmux new-session -s "$SESS" "bash -lc \"$RUN\""
fi
exec bash -lc "$RUN"                                          # no tmux: run directly
