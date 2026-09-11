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
    "cyan": "\x1b[38;2;34;211;238m",
    "gray": "\x1b[90m",
    "slate": "\x1b[38;2;71;85;105m",
    "green": "\x1b[38;2;16;185;129m",
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


# --- full seat chrome (faithful port of the SYGNIF pi seat's render.ts) ------
# Truecolor palette copied verbatim from the pi seat so the terminal matches the
# SYGNIF brand exactly: cyan border/accent, slate meta, green ok.
import re as _re

SIGIL = "Σ"
_TC = {
    "cyan": "38;2;34;211;238",   # #22D3EE accent — border, headings, ❯
    "green": "38;2;16;185;129",  # #10B981 ctx ok
    "slate": "38;2;71;85;105",   # #475569 dim — rules, separators, meta
}


def tc(key: str, s: str, bold: bool = False) -> str:
    """Paint s in a truecolor palette entry (no-op when colour is off)."""
    if not COLOR or not s:
        return s
    codes = _TC.get(key, "")
    if bold:
        codes = (codes + ";1") if codes else "1"
    return f"\x1b[{codes}m{s}\x1b[0m"


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


def frame_width() -> int:
    """Full terminal width — the prompt frame and seat box both span it (pi parity)."""
    return width()


def banner() -> str:
    """SYGNIF wordmark in brand cyan, or '' when it should not show. Reversible:
    SYGNIF_PY_BANNER=0/off hides it; skipped off-TTY/PIX or when too narrow."""
    if not PIX:
        return ""
    if os.environ.get("SYGNIF_PY_BANNER", "").strip().lower() in ("0", "off", "false", "no"):
        return ""
    w = max(len(l) for l in WORDMARK)
    if frame_width() < w:
        return ""
    return "\n".join(tc("cyan", l) for l in WORDMARK)


def box(title: str, body_lines, tone: str = "cyan") -> str:
    """Rounded full-width box with a bold title inset in the top rule — the exact
    geometry of the pi seat's render.ts box(): cols = terminal width, inner = cols-4."""
    W = frame_width()
    inner = W - 4
    tag = f" {title} " if title else ""
    fill = max(0, W - 2 - 1 - vlen(tag))
    out = [tc(tone, "╭─") + tc(tone, tag, bold=True) + tc(tone, "─" * fill + "╮")]
    for row in body_lines:
        gap = " " * max(0, inner - vlen(row))
        out.append(tc(tone, "│") + " " + row + gap + " " + tc(tone, "│"))
    out.append(tc(tone, "╰" + "─" * (W - 2) + "╯"))
    return "\n".join(out)


def seat_box(model_id: str, n_tools: int, extras: str, switch_line: str, help_line: str, probe: str = "") -> None:
    """The 'Σ SYGNIF seat' welcome box, same box language as the pi seat."""
    if not PIX:
        print(f"{SIGIL} SYGNIF seat — {model_id} · {n_tools} tools · {extras}")
        print("  " + switch_line)
        print("  " + help_line)
        if probe:
            print("  " + probe)
        return
    body = [
        f"{tc('cyan', model_id, bold=True)} {tc('slate', '·')} {n_tools} tools {tc('slate', '·')} {tc('slate', extras)}",
        tc("slate", switch_line),
        tc("slate", help_line),
    ]
    if probe:
        body.append(tc("slate", probe))
    print(box(f"{SIGIL} SYGNIF seat", body, "cyan"))


def status_bar(model: str, used, window, tps, frame: bool = True) -> str:
    """The strip under the prompt: ○ idle · ctx · tps · model — a faithful port of
    render.ts statusBar(). `frame` makes it the box's bottom rule (╰─ … ─╯)."""
    W = frame_width()
    dot = tc("slate", "○ idle")
    pct = round((used / window) * 100) if (used is not None and window) else None
    win = fmt_k(window) if window else "0"
    ctxval = "—" if used is None else (f"{fmt_k(used)}/{win}" + (f" {pct}%" if pct is not None else ""))
    ctx = tc("slate", "ctx ") + tc("green" if pct is not None else "slate", ctxval)
    tps_s = tc("slate", "— tps") if tps is None else tc("cyan", f"~{tps} tps")
    model_s = tc("slate", model)
    sep = tc("slate", " · ")
    lead = (tc("cyan", "╰") + tc("slate", "─ ")) if frame else tc("slate", "╶─ ")
    segs = [dot, ctx, tps_s, model_s]
    body = sep.join(segs)
    while (vlen(lead) + vlen(body) + 2) > W and len(segs) > 1:
        segs.pop()
        body = sep.join(segs)
    fill = max(0, W - vlen(lead) - vlen(body) - 2)
    tail = (tc("slate", "─" * fill) + tc("cyan", "╯")) if frame else tc("slate", "─" * fill + "╴")
    return lead + body + " " + tail


def status_line(model: str, used, window, tps, turns: int = 0, state: str = "idle") -> None:
    """Standalone status readout (fallback when the boxed prompt is not used)."""
    if not PIX:
        return
    print(status_bar(model, used, window, tps, frame=False))


def prompt_glyph() -> str:
    """The ❯ line's left gutter + cyan chevron: '│ ❯ ' (visible width 4)."""
    return tc("cyan", "│") + " " + tc("cyan", "❯", bold=True) + " "


def frame_top() -> str:
    W = frame_width()
    return tc("cyan", "╭" + "─" * max(0, W - 2) + "╮")


def frame_bottom() -> str:
    W = frame_width()
    return tc("cyan", "╰" + "─" * max(0, W - 2) + "╯")


def prompt_str() -> str:
    """Fallback prompt (non-TTY / box disabled): cyan top rule then '│ ❯ '."""
    if not PIX:
        return "you> "
    return frame_top() + "\n" + prompt_glyph()


def read_prompt_box(model, used, window, tps, turns: int = 0) -> str:
    """Draw the pi-style prompt box — top rule, the '│ ❯ ' line with a right edge,
    and the status bar as the bottom rule — then read one line inside it.

    Cooked-mode read (sys.stdin.readline) rather than the readline module: readline
    repaints the line from column 0 and would wipe the pre-drawn bottom rule.
    Trade-off: no arrow-key history in the boxed reader; SYGNIF_PY_PIX_BOX=0 falls
    back to a plain readline prompt (with history) and the status line above it."""
    boxed = PIX and TTY and os.environ.get("SYGNIF_PY_PIX_BOX", "1") != "0"
    if not boxed:
        if PIX:
            status_line(model, used, window, tps, turns)
        return input(prompt_str() if PIX else "you> ")
    W = frame_width()
    edge = tc("cyan", "│")
    line = prompt_glyph() + " " * max(0, W - 4 - 1) + edge
    bar = status_bar(model, used, window, tps, frame=True)
    sys.stdout.write("\n" + frame_top() + "\n" + line + "\n" + bar + "\r")
    sys.stdout.write("\x1b[1A\x1b[5G")  # up to the ❯ row, column after '│ ❯ '
    sys.stdout.flush()
    s = sys.stdin.readline()  # cooked mode: terminal echoes inside the box
    if s == "":
        raise EOFError
    text = s.rstrip("\n")
    sys.stdout.write("\r\x1b[2K" + frame_bottom() + "\n")  # close the frame
    sys.stdout.flush()
    return text
