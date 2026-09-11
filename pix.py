#!/usr/bin/env python3
"""SYGNIF py — pix terminal UI.

A dependency-free ANSI chrome for the seat REPL, ported from the SYGNIF pi seat
(the SYGNIF_PIX layer): a framed ❯ promptbox, an idle info line
(model · ctx · tps · turns), per-turn separators, and clean tool lines — instead
of the raw `you>` / `SYGNIF>` prints.

No third-party deps. Honours NO_COLOR, TERM=dumb, and non-TTY output (a pipe
gets clean plain text with no escape codes). Enable/disable the whole layer with
SYGNIF_PY_PIX (default: on when stdout is a TTY).
"""
from __future__ import annotations

import os
import shutil
import sys
from datetime import datetime

TTY = sys.stdout.isatty()
PIX = os.environ.get("SYGNIF_PY_PIX", "1" if TTY else "0") != "0"
COLOR = TTY and os.environ.get("NO_COLOR") is None and os.environ.get("TERM") != "dumb"

# --- ANSI -------------------------------------------------------------------

_RESET = "\x1b[0m"
_CODES = {
    "dim": "\x1b[2m",
    "bold": "\x1b[1m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "magenta": "\x1b[35m",
    "cyan": "\x1b[36m",
    "gray": "\x1b[90m",
}


def paint(code: str, s: str) -> str:
    if not COLOR or not s:
        return s
    return f"{_CODES.get(code, '')}{s}{_RESET}"


def dim(s: str) -> str:
    return paint("dim", s)


def bold(s: str) -> str:
    return paint("bold", s)


def cyan(s: str) -> str:
    return paint("cyan", s)


def gray(s: str) -> str:
    return paint("gray", s)


# --- helpers ----------------------------------------------------------------


def width(default: int = 80) -> int:
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except Exception:  # noqa: BLE001
        return default


def fmt_k(n) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "?"
    if n >= 1000:
        return f"{n / 1000:.1f}k" if n < 10000 else f"{round(n / 1000)}k"
    return str(n)


def rule(char: str = "─") -> str:
    return dim(char * max(8, width()))


# --- chrome -----------------------------------------------------------------


def banner_line(text: str) -> None:
    """One dim system line (endpoint/model/tools readout, notices)."""
    print(dim(text))


def turn_separator(n: int) -> None:
    """`── turn N · HH:MM:SS ──`, a quiet rule per turn so the transcript reads
    as a sequence of exchanges rather than one wall of text."""
    if not PIX:
        return
    clock = datetime.now().strftime("%H:%M:%S")
    print(dim(f"── turn {n} · {clock} ──"))


def info_line(model: str, used, window, tps, turns: int) -> None:
    """The PIX promptbox readout: model · ctx occupancy · last tps · turn count."""
    if not PIX:
        return
    parts = [model]
    if used is not None and window:
        pct = round((used / window) * 100)
        parts.append(f"ctx {fmt_k(used)}/{fmt_k(window)} {pct}%")
    elif window:
        parts.append(f"ctx window {fmt_k(window)}")
    if tps is not None:
        parts.append(f"~{tps} tps")
    if turns > 0:
        parts.append(f"{turns} turn{'' if turns == 1 else 's'}")
    print(dim("  Σ " + " · ".join(parts)))


def prompt_str() -> str:
    """The ❯ prompt passed to input(). A framed prompt when PIX is on: a dim
    top rule then a bold cyan chevron; a plain `you> ` otherwise."""
    if not PIX:
        return "you> "
    return cyan("╭" + "─" * max(8, width() - 2)) + "\n" + (cyan(bold("❯")) if COLOR else "❯") + " "


def reply_header() -> None:
    """Marker before a streamed/printed assistant reply."""
    if PIX:
        print(cyan(bold("◆ SYGNIF")))
    else:
        print("\nSYGNIF>", end=" ")


def tool_start(name: str, args_preview: str) -> None:
    arrow = cyan("→") if COLOR else "→"
    print(f"  {arrow} {bold(name)}{dim('(' + args_preview + ')')}")


def tool_end(preview: str, is_error: bool = False) -> None:
    arrow = paint("red", "←") if is_error else (paint("green", "←") if COLOR else "←")
    print(f"  {arrow} {dim(preview)}")


def notice(text: str, kind: str = "dim") -> None:
    print(paint(kind if kind in _CODES else "dim", text))


class LiveText:
    """Prints streamed assistant text live, but stops at the first ``` fence so a
    tool-call block is never dumped raw — a clean `→ tool` line replaces it.
    Holds back a 2-char tail so a fence split across deltas is never printed."""

    def __init__(self, on_first=None):
        self.buf = ""
        self.printed = 0
        self.suppressed = False
        self._on_first = on_first
        self._fired = False

    def _fire(self):
        if not self._fired:
            self._fired = True
            if self._on_first:
                self._on_first()

    def _write(self, s: str) -> None:
        if not s:
            return
        self._fire()
        sys.stdout.write(s)
        sys.stdout.flush()

    def feed(self, delta: str) -> None:
        self.buf += delta
        if self.suppressed:
            return
        idx = self.buf.find("```")
        if idx == -1:
            safe = len(self.buf) - 2  # keep a tail; a partial ``` may still form
            if safe > self.printed:
                self._write(self.buf[self.printed:safe])
                self.printed = safe
        else:
            if idx > self.printed:
                self._write(self.buf[self.printed:idx])
            self.printed = idx
            self.suppressed = True

    def close(self) -> bool:
        """Flush the remainder (when no fence appeared). Returns True if any
        assistant prose was actually printed."""
        if not self.suppressed and self.printed < len(self.buf):
            self._write(self.buf[self.printed:])
            self.printed = len(self.buf)
        if self._fired:
            sys.stdout.write("\n")
            sys.stdout.flush()
        return self._fired


def hello(name: str, model_key: str, model_id: str, endpoint: str) -> None:
    """Startup banner, PIX-styled."""
    if PIX:
        print(rule())
        print(f"{cyan(bold('SYGNIF'))} {dim('py')}  ·  {model_key} {dim('(' + model_id + ')')}")
        print(dim(f"  {endpoint}"))
        print(dim("  type a prompt, or /help for commands"))
    else:
        print(f"SYGNIF py — {model_key} ({model_id}) @ {endpoint}")
        print("Type a prompt, or /help for commands.")


# --- full seat chrome (ported from the SYGNIF pi seat: wordmark + Σ box) -----

import re as _re

SIGIL = "Σ"

# SYGNIF block wordmark (figlet "ANSI Shadow") — the same mark the pi seat shows
# at boot. Reversible: SYGNIF_PY_BANNER=0 hides it; auto-skipped off-TTY/narrow.
WORDMARK = [
    "███████╗██╗   ██╗ ██████╗ ███╗   ██╗██╗███████╗",
    "██╔════╝╚██╗ ██╔╝██╔════╝ ████╗  ██║██║██╔════╝",
    "███████╗ ╚████╔╝ ██║  ███╗██╔██╗ ██║██║█████╗",
    "╚════██║  ╚██╔╝  ██║   ██║██║╚██╗██║██║██╔══╝",
    "███████║   ██║   ╚██████╔╝██║ ╚████║██║██║",
    "╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝",
]

_ANSI_RE = _re.compile(r"\x1b\[[0-9;]*m")


def vlen(s: str) -> int:
    """Visible width: length with ANSI SGR codes stripped, for box padding."""
    return len(_ANSI_RE.sub("", s))


def banner() -> str:
    """SYGNIF wordmark in brand cyan, or '' when it should not show. Reversible:
    SYGNIF_PY_BANNER=0/off hides it; skipped off-TTY, when PIX is off, or when the
    terminal is narrower than the mark (so it never wrap-mangles)."""
    if not PIX:
        return ""
    if os.environ.get("SYGNIF_PY_BANNER", "").strip().lower() in ("0", "off", "false", "no"):
        return ""
    w = max(len(l) for l in WORDMARK)
    if width() < w:
        return ""
    return "\n".join(cyan(l) for l in WORDMARK)


def seat_box(model_id: str, n_tools: int, extras: str, switch_line: str, help_line: str) -> None:
    """The framed 'Σ SYGNIF seat' welcome box: model · tools · extras, then the
    model-switch legend and the session-command legend. Plain fallback off-PIX."""
    title = f"{SIGIL} SYGNIF seat"
    body = [
        f"{bold(model_id)} {dim('·')} {n_tools} tools {dim('·')} {dim(extras)}",
        dim(switch_line),
        dim(help_line),
    ]
    if not PIX:
        print(f"{title} — {model_id} · {n_tools} tools · {extras}")
        print("  " + switch_line)
        print("  " + help_line)
        return
    w = min(max([vlen(title) + 1] + [vlen(b) for b in body]), max(20, width() - 4))
    print(cyan("╭─ ") + cyan(bold(title)) + cyan(" " + "─" * max(0, w - vlen(title) - 1) + "╮"))
    for b in body:
        print(cyan("│ ") + b + " " * max(0, w - vlen(b)) + cyan(" │"))
    print(cyan("╰" + "─" * (w + 2) + "╯"))


def status_line(model: str, used, window, tps, turns: int, state: str = "idle") -> None:
    """The idle status readout above the prompt: state dot, ctx occupancy, last
    tps, model, turn count — the fields the pi seat pins under its prompt box."""
    if not PIX:
        return
    dot = cyan("●") if state != "idle" else gray("○")
    parts = []
    if used is not None and window:
        parts.append(f"ctx {fmt_k(used)}/{fmt_k(window)} {round(used / window * 100)}%")
    else:
        parts.append("ctx —")
    parts.append(f"~{tps} tps" if tps is not None else "— tps")
    parts.append(model)
    if turns > 0:
        parts.append(f"{turns} turn{'' if turns == 1 else 's'}")
    print(f"  {dot} {dim(state + '  ·  ' + '  ·  '.join(parts))}")
