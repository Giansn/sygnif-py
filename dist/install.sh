#!/usr/bin/env sh
# SYGNIF py — one-line installer for Linux / macOS.
#
#   curl -fsSL https://<host>/install.sh | sh
#
# Downloads the SYGNIF py package, unpacks it to ~/.sygnif-py (override with
# SYGNIF_PY_HOME), and drops a `sygnif` launcher into ~/.local/bin.
#
# Env knobs:
#   SYGNIF_PY_BASE_URL  where to fetch sygnif-py.tar.gz from (default below)
#   SYGNIF_PY_HOME      install dir (default: ~/.sygnif-py)
#   SYGNIF_PY_BIN       launcher dir (default: ~/.local/bin)
set -eu

BASE_URL="${SYGNIF_PY_BASE_URL:-https://raw.githubusercontent.com/Giansn/sygnif-py/main/dist}"
HOME_DIR="${SYGNIF_PY_HOME:-$HOME/.sygnif-py}"
BIN_DIR="${SYGNIF_PY_BIN:-$HOME/.local/bin}"
TARBALL="sygnif-py.tar.gz"

say() { printf '\033[36m[sygnif-py]\033[0m %s\n' "$1"; }
die() { printf '\033[31m[sygnif-py] %s\033[0m\n' "$1" >&2; exit 1; }

# --- prerequisites ----------------------------------------------------------
PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
[ -n "$PY" ] || die "Python 3.8+ is required but was not found. Install it and re-run."

FETCH=""
if command -v curl >/dev/null 2>&1; then FETCH="curl -fsSL";
elif command -v wget >/dev/null 2>&1; then FETCH="wget -qO-";
else die "need curl or wget to download."; fi

# --- download + unpack ------------------------------------------------------
say "installing to $HOME_DIR (from $BASE_URL)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
say "downloading $TARBALL ..."
$FETCH "$BASE_URL/$TARBALL" > "$TMP/$TARBALL" || die "download failed: $BASE_URL/$TARBALL"
[ -s "$TMP/$TARBALL" ] || die "downloaded file is empty."

mkdir -p "$HOME_DIR"
tar -xzf "$TMP/$TARBALL" -C "$HOME_DIR" || die "unpack failed."
# tarball is packed flat (files at its root), so files land directly in HOME_DIR.
[ -f "$HOME_DIR/seat.py" ] || die "package looks incomplete (no seat.py in $HOME_DIR)."
chmod +x "$HOME_DIR/sygnif.sh" "$HOME_DIR/sygnif-centre.sh" "$HOME_DIR/sygnif-commander.sh" "$HOME_DIR/sygnif-desk.sh" "$HOME_DIR/sygnif-nexus.sh" 2>/dev/null || true

# --- launchers on PATH ------------------------------------------------------
mkdir -p "$BIN_DIR"
# The seat, the Centre (knot point), the commander (hands), and the Desk (the
# browser dashboard) each get a launcher.
for name in sygnif:sygnif.sh sygnif-centre:sygnif-centre.sh sygnif-commander:sygnif-commander.sh sygnif-desk:sygnif-desk.sh sygnif-nexus:sygnif-nexus.sh; do
  cmd="${name%%:*}"; script="${name##*:}"
  cat > "$BIN_DIR/$cmd" <<EOF
#!/usr/bin/env sh
exec "$HOME_DIR/$script" "\$@"
EOF
  chmod +x "$BIN_DIR/$cmd"
done

say "installed. launchers: $BIN_DIR/{sygnif, sygnif-desk, sygnif-nexus, sygnif-centre, sygnif-commander}"
case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *) say "NOTE: $BIN_DIR is not on your PATH — add it, e.g.:"
     printf '        echo '\''export PATH="%s:$PATH"'\'' >> ~/.profile\n' "$BIN_DIR" ;;
esac
say "run the seat:      sygnif           (or: $HOME_DIR/sygnif.sh)"
say "the dashboard:     sygnif-desk      (chat + workflows in your browser, http://127.0.0.1:8899)"
say "the nexus:         sygnif-nexus     (portal board over tmux, http://127.0.0.1:8910)"
say "the knot point:    sygnif-centre    (host state, notes, knowledge)"
say "the hands:         sygnif-commander (sandboxed fs/exec; mints its own token)"
say ""
say ""
say "FIRST RUN: type  sygnif  once. Because the default model is Claude Fable 5.1,"
say "the first launch walks you through logging in to your Claude Pro/Max subscription"
say "(via the official claude CLI) and sets up a pentest workspace at ~/sygnif-pentest."
say "        sygnif"
say ""
say "prefer a free model with no login?  in the seat run:  /model openrouter-free"
say "        (make a free key at openrouter.ai, then: export OPENROUTER_API_KEY=sk-or-...)"
say "add or change models in $HOME_DIR/config.json or ~/.sygnif/sygnif-py.json"
