#!/usr/bin/env python3
"""SYGNIF py — terminal renderer (markdown -> ANSI), ported from the SYGNIF pi
seat's render.ts.

The seat speaks markdown; a terminal does not. Without help a model reply with a
GFM table or a fenced code block lands as raw `|` pipes and literal ``` fences.
This module is the fix: a dependency-free markdown->ANSI engine so assistant text
reads cleanly *inside* the cyan SYGNIF box — aligned tables, real bold, framed
code, tidy headings and lists — plus the framed prompt, the framed notices and
the full-width status bar that make up the pi seat's house style.

Design constraints (same ethos as pi's render.ts):
  * No TUI framework. stdlib + ANSI + box-drawing only.
  * SYGNIF is cyan (#22D3EE). Secondary brand colours used sparingly for
    hierarchy; body text stays the terminal's own fg so it reads on any theme.
  * The sigil is Σ. Assistant prose lives in a cyan rounded box; fenced code
    breaks out flush-left so it pastes into a shell exactly as written.
  * ANSI-aware throughout: every width/pad/wrap measures *visible* columns, never
    raw string length, so colour codes never break alignment.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import threading
import time

# --- palette ----------------------------------------------------------------
# SGR parameter strings (the bit between "\x1b[" and "m"). Truecolor, taken
# straight from the SYGNIF skin so the terminal matches the rest of the brand.
CYAN = "38;2;34;211;238"   # #22D3EE  SYGNIF accent — border, headings
SKY = "38;2;14;165;233"    # #0EA5E9  secondary rule / code bar
GREEN = "38;2;16;185;129"  # #10B981  labels, inline code, ok
SLATE = "38;2;71;85;105"   # #475569  dim — rules, separators, meta
AMBER = "38;2;251;191;36"  # #FBBF24  warnings
RED = "38;2;248;113;113"   # #F87171  errors
BOLD = "1"
ITALIC = "3"
STRIKE = "9"

SIGIL = "Σ"

# --- colour gate ------------------------------------------------------------
# On by default for an interactive TTY; off for pipes / NO_COLOR / TERM=dumb so
# captured or redirected output stays clean. Mirrors pix.py's gate exactly.
_TTY = sys.stdout.isatty()
COLOR = _TTY and os.environ.get("NO_COLOR") is None and os.environ.get("TERM") != "dumb"


def set_color(on: bool) -> None:
    global COLOR
    COLOR = on


def paint(codes: str, s: str) -> str:
    """Wrap `s` in an SGR sequence (no-op when colour is off or codes empty)."""
    return f"\x1b[{codes}m{s}\x1b[0m" if COLOR and codes else s


# --- width helpers (ANSI- and wide-char-aware) ------------------------------

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def strip(s: str) -> str:
    return _ANSI.sub("", s)


def is_wide(cp: int) -> bool:
    """East-Asian / emoji code points that occupy two terminal columns."""
    return (
        (0x1100 <= cp <= 0x115F)
        or (0x2E80 <= cp <= 0xA4CF)
        or (0xAC00 <= cp <= 0xD7A3)
        or (0xF900 <= cp <= 0xFAFF)
        or (0xFE30 <= cp <= 0xFE4F)
        or (0xFF00 <= cp <= 0xFF60)
        or (0xFFE0 <= cp <= 0xFFE6)
        or (0x1F300 <= cp <= 0x1FAFF)
        or (0x20000 <= cp <= 0x3FFFD)
    )


def vw(s: str) -> int:
    """Visible column width of a (possibly styled) string."""
    w = 0
    for ch in strip(s):
        w += 2 if is_wide(ord(ch)) else 1
    return w


def slice_width(s: str, width: int) -> str:
    """Longest prefix of a plain (ANSI-free) string with visible width <= width."""
    w = 0
    out = ""
    for ch in s:
        cw = 2 if is_wide(ord(ch)) else 1
        if w + cw > width:
            break
        out += ch
        w += cw
    return out or s[:1]


def pad(s: str, width: int, align: str = "left") -> str:
    """Pad a styled cell to `width` columns under the given alignment."""
    gap = max(0, width - vw(s))
    if align == "right":
        return " " * gap + s
    if align == "center":
        left = gap >> 1
        return " " * left + s + " " * (gap - left)
    return s + " " * gap


# --- inline spans -> styled runs --------------------------------------------
# The emphasis the model actually emits — **bold**, *italic*, `code`, ~~strike~~,
# [text](url). Underscore emphasis is deliberately NOT honoured: it would mangle
# identifiers like read_skill / sygnif-dev that pepper SYGNIF output.
_INLINE = re.compile(
    r"\*\*([^*]+?)\*\*|\*([^*]+?)\*|`([^`]+?)`|~~([^~]+?)~~|\[([^\]]+?)\]\(([^)]+?)\)"
)


def parse_inline(src: str):
    """List of (text, codes) runs for a single line of inline markdown."""
    runs = []
    rest = src
    while rest:
        m = _INLINE.search(rest)
        if not m:
            runs.append((rest, ""))
            break
        if m.start() > 0:
            runs.append((rest[: m.start()], ""))
        if m.group(1) is not None:
            runs.append((m.group(1), BOLD))
        elif m.group(2) is not None:
            runs.append((m.group(2), ITALIC))
        elif m.group(3) is not None:
            runs.append((m.group(3), GREEN))
        elif m.group(4) is not None:
            runs.append((m.group(4), f"{SLATE};{STRIKE}"))
        elif m.group(5) is not None:
            runs.append((m.group(5), f"{CYAN};4"))
            url = m.group(6) or ""
            if url and url != m.group(5):
                runs.append((f" ({url})", SLATE))
        rest = rest[m.end():]
    return [(t, c) for (t, c) in runs if t]


def plain(s: str) -> str:
    """Strip inline markers to recover the plain text (used for width math)."""
    s = re.sub(r"\*\*|\*|`|~~", "", s)
    s = re.sub(r"\[([^\]]+?)\]\([^)]+?\)", r"\1", s)
    return s


def render_runs(line) -> str:
    return "".join(paint(codes, text) for (text, codes) in line)


def wrap_runs(runs, width: int):
    """Greedy word-wrap styled runs to `width` columns, preserving each run's style."""
    words = []
    for (text, codes) in runs:
        for t in re.split(r"\s+", text):
            if t:
                words.append((t, codes))
    lines = []
    cur = []
    cur_w = 0
    for (wtext, wcodes) in words:
        text = wtext
        w = vw(text)
        while w > width:
            if cur_w > 0:
                lines.append(cur)
                cur = []
                cur_w = 0
            head = slice_width(text, width)
            lines.append([(head, wcodes)])
            text = text[len(head):]
            w = vw(text)
        sep = 1 if cur_w > 0 else 0
        if cur_w > 0 and cur_w + sep + w > width:
            lines.append(cur)
            cur = []
            cur_w = 0
        if cur_w > 0:
            cur.append((" ", ""))
            cur_w += 1
        cur.append((text, wcodes))
        cur_w += w
    if cur:
        lines.append(cur)
    return lines if lines else [[]]


def wrap_plain(text: str, width: int, codes: str = ""):
    """Wrap plain text to width, painting every produced line with `codes`."""
    out = []
    for ln in wrap_runs([(text, "")], width):
        s = "".join(t for (t, _c) in ln)
        out.append(paint(codes, s) if codes else s)
    return out


# --- block renderers (each returns a list of unpadded, styled lines) --------


def _render_heading(text: str, level: int, width: int):
    lines = wrap_plain(plain(text), width, f"{CYAN};{BOLD}")
    if level <= 2:
        lines.append(paint(SLATE, "─" * width))
    return lines


def _render_paragraph(text: str, width: int):
    return [render_runs(ln) for ln in wrap_runs(parse_inline(text), width)]


def _render_hr(width: int):
    return [paint(SLATE, "─" * width)]


def _render_quote(text: str, width: int):
    bar = paint(SLATE, "▏") + " "
    out = []
    for ln in wrap_runs(parse_inline(text), width - 2):
        out.append(bar + paint(f"{SLATE};{ITALIC}", strip(render_runs(ln))))
    return out


def _render_code(lang: str, code, width: int):
    bar = paint(SKY, "▎") + " "    # solid sky bar — start of a logical line
    cont = paint(SLATE, "╎") + " "  # dashed dim bar — wrapped continuation
    inner = max(8, width - 2)
    out = []
    if lang:
        out.append(paint(SLATE, lang))
    code = list(code)
    while code and not code[0].strip():
        code.pop(0)
    while code and not code[-1].strip():
        code.pop()
    for raw in code:
        line = raw.replace("\t", "  ")
        if not line:
            out.append(bar)
            continue
        lead = bar
        while vw(line) > inner:
            head = slice_width(line, inner)
            out.append(lead + head)
            line = line[len(head):]
            lead = cont
        out.append(lead + line)
    return out


def _render_list(raw, width: int):
    items = []
    for line in raw:
        m = re.match(r"^(\s*)([-*+]|\d+[.)])\s+(.*)$", line)
        if m:
            items.append([int(len(m.group(1)) // 2), m.group(2), m.group(3)])
        elif items:
            items[-1][2] += " " + line.strip()
    out = []
    for indent, marker, text in items:
        lead = "  " * indent
        ordered = bool(re.search(r"\d", marker))
        bullet = re.sub(r"[.)]", ".", marker) if ordered else "•"
        prefix = lead + paint(CYAN, bullet) + " "
        prefix_w = indent * 2 + vw(bullet) + 1
        wrapped = [render_runs(ln) for ln in wrap_runs(parse_inline(text), max(8, width - prefix_w))]
        for i, ln in enumerate(wrapped):
            out.append((prefix + ln) if i == 0 else (" " * prefix_w + ln))
    return out


def _split_row(line: str):
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [c.strip() for c in s.split("|")]


def _is_table_delim(line: str) -> bool:
    return bool(re.match(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$", line))


def _render_table(header: str, delim: str, body, width: int):
    head = _split_row(header)
    n = len(head)

    def align_of(d: str) -> str:
        left = d.startswith(":")
        right = d.endswith(":")
        return "center" if (left and right) else ("right" if right else "left")

    aligns = [align_of(d) for d in _split_row(delim)]
    rows = []
    for b in body:
        cells = _split_row(b)
        while len(cells) < n:
            cells.append("")
        rows.append(cells[:n])

    widths = []
    for c, h in enumerate(head):
        w = vw(plain(h))
        for row in rows:
            w = max(w, vw(plain(row[c] if c < len(row) else "")))
        widths.append(w)

    gutter = 2
    budget = max(n * 4, width - gutter * (n - 1))

    def total():
        return sum(widths)

    while total() > budget:
        idx = -1
        mx = 4
        for c in range(n):
            if widths[c] > mx:
                mx = widths[c]
                idx = c
        if idx < 0:
            break
        widths[idx] -= 1

    def align(c: int) -> str:
        return aligns[c] if c < len(aligns) else "left"

    def cell_lines(text: str, c: int, codes: str):
        if codes:
            lines = wrap_plain(plain(text), widths[c], codes)
        else:
            lines = [render_runs(ln) for ln in wrap_runs(parse_inline(text), widths[c])]
        return [pad(l, widths[c], align(c)) for l in lines]

    def assemble(cols):
        h = max([1] + [len(c) for c in cols])
        lines = []
        for r in range(h):
            lines.append("  ".join(cols[c][r] if r < len(cols[c]) else " " * widths[c] for c in range(len(cols))))
        return lines

    out = []
    out.extend(assemble([cell_lines(h, c, f"{CYAN};{BOLD}") for c, h in enumerate(head)]))
    out.append("  ".join(paint(SLATE, "─" * w) for w in widths))
    for row in rows:
        out.extend(assemble([cell_lines(cell, c, "") for c, cell in enumerate(row)]))
    return out


def _opens_block(line: str, nxt) -> bool:
    return bool(
        re.match(r"^\s*```", line)
        or re.match(r"^(#{1,6})\s+", line)
        or re.match(r"^\*\*[^*]+\*\*:?\s*$", line)
        or re.match(r"^\s*>\s?", line)
        or re.match(r"^\s*([-*_])(\s*\1){2,}\s*$", line)
        or re.match(r"^\s*([-*+]|\d+[.)])\s+", line)
        or ("|" in line and nxt is not None and _is_table_delim(nxt))
    )


def render_markdown(md: str, width: int) -> str:
    """Render a markdown string to styled, unpadded lines fitted to `width`."""
    lines = md.replace("\r\n", "\n").split("\n")
    blocks = []
    i = 0

    def blank(s) -> bool:
        return s is None or re.match(r"^\s*$", s) is not None

    while i < len(lines):
        line = lines[i]
        if blank(line):
            i += 1
            continue

        m = re.match(r"^\s*```\s*([\w+#.-]*)\s*$", line)
        if m:
            lang = m.group(1) or ""
            code = []
            i += 1
            while i < len(lines) and not re.match(r"^\s*```\s*$", lines[i]):
                code.append(lines[i])
                i += 1
            if i < len(lines):
                i += 1  # closing fence
            blocks.append(_render_code(lang, code, width))
            continue
        if "|" in line and _is_table_delim(lines[i + 1] if i + 1 < len(lines) else ""):
            header = line
            delim = lines[i + 1]
            body = []
            i += 2
            while i < len(lines) and not blank(lines[i]) and "|" in lines[i]:
                body.append(lines[i])
                i += 1
            blocks.append(_render_table(header, delim, body, width))
            continue
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            blocks.append(_render_heading(m.group(2), len(m.group(1)), width))
            i += 1
            continue
        m = re.match(r"^\*\*([^*]+?)\*\*:?\s*$", line)
        if m:
            blocks.append(_render_heading(m.group(1), 2, width))
            i += 1
            continue
        if re.match(r"^\s*([-*_])(\s*\1){2,}\s*$", line):
            blocks.append(_render_hr(width))
            i += 1
            continue
        if re.match(r"^\s*>\s?", line):
            q = []
            while i < len(lines) and re.match(r"^\s*>\s?", lines[i]):
                q.append(re.sub(r"^\s*>\s?", "", lines[i]))
                i += 1
            blocks.append(_render_quote(" ".join(q), width))
            continue
        if re.match(r"^\s*([-*+]|\d+[.)])\s+", line):
            lst = []
            while i < len(lines) and not blank(lines[i]) and (
                re.match(r"^\s*([-*+]|\d+[.)])\s+", lines[i]) or re.match(r"^\s+\S", lines[i])
            ):
                lst.append(lines[i])
                i += 1
            blocks.append(_render_list(lst, width))
            continue
        # paragraph: gather until a blank line or the start of another block
        para = []
        while i < len(lines) and not blank(lines[i]) and not _opens_block(
            lines[i], lines[i + 1] if i + 1 < len(lines) else None
        ):
            para.append(lines[i])
            i += 1
        if not para:
            para.append(lines[i])
            i += 1  # safety: always advance
        blocks.append(_render_paragraph(" ".join(para), width))

    out = []
    for idx, b in enumerate(blocks):
        if idx:
            out.append("")
        out.extend(b)
    return "\n".join(out)


# --- framing ----------------------------------------------------------------
MAX_WIDTH = 100


def _cols(default: int = 80) -> int:
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except Exception:  # noqa: BLE001
        return default


def term_width() -> int:
    return min(_cols(), MAX_WIDTH)


def frame_width() -> int:
    """Full terminal width, uncapped — the prompt frame and status bar match the
    width readline (here: input()) actually wraps the typed line at."""
    return _cols()


def _box(title: str, body: str, codes: str) -> str:
    cols = term_width()
    inner = cols - 4  # "│ " … " │"
    tag = f" {title} " if title else ""
    fill = max(0, cols - 2 - 1 - vw(tag))
    out = [paint(codes, "╭─") + paint(f"{codes};{BOLD}", tag) + paint(codes, "─" * fill + "╮")]
    for row in body.split("\n"):
        gap = " " * max(0, inner - vw(row))
        out.append(paint(codes, "│") + " " + row + gap + " " + paint(codes, "│"))
    out.append(paint(codes, "╰" + "─" * (cols - 2) + "╯"))
    return "\n".join(out)


def _split_segments(md: str):
    """Split into prose / fenced-code segments (code breaks out of the box)."""
    lines = md.replace("\r\n", "\n").split("\n")
    segs = []
    prose = []

    def flush():
        if prose:
            segs.append(("prose", "\n".join(prose), "", []))

    i = 0
    while i < len(lines):
        m = re.match(r"^\s*```\s*([\w+#.-]*)\s*$", lines[i])
        if m:
            flush()
            prose.clear()
            code = []
            i += 1
            while i < len(lines) and not re.match(r"^\s*```\s*$", lines[i]):
                code.append(lines[i])
                i += 1
            if i < len(lines):
                i += 1  # closing fence
            while code and not code[0].strip():
                code.pop(0)
            while code and not code[-1].strip():
                code.pop()
            segs.append(("code", "", m.group(1) or "", code))
        else:
            prose.append(lines[i])
            i += 1
    flush()
    return [s for s in segs if (len(s[3]) > 0 if s[0] == "code" else s[1].strip())]


def render_assistant(text: str) -> str:
    """An assistant turn: prose boxed in cyan, fenced code broken out for copy."""
    W = term_width()
    inner = W - 4

    def dash(n: int) -> str:
        return "─" * max(0, n)

    def top(label: str) -> str:
        tag = f" {label} "
        return paint(CYAN, "╭─") + paint(f"{CYAN};{BOLD}", tag) + paint(CYAN, dash(W - 3 - vw(tag)) + "╮")

    def bottom() -> str:
        return paint(CYAN, "╰" + dash(W - 2) + "╯")

    def open_code(lang: str) -> str:
        label = f" {lang} " if lang else ""
        return paint(CYAN, "├─") + paint(SLATE, label) + paint(CYAN, dash(W - 3 - vw(label)) + "┤")

    def close_code() -> str:
        return paint(CYAN, "├" + dash(W - 2) + "┤")

    segs = _split_segments(text)
    if not segs:
        segs = [("prose", "", "", [])]

    out = []
    for i, (kind, body, lang, codelines) in enumerate(segs):
        if i == 0:
            out.append(top(f"{SIGIL} SYGNIF · {lang}" if kind == "code" and lang else f"{SIGIL} SYGNIF"))
        elif kind == "code":
            out.append(open_code(lang))
        else:
            out.append(close_code())
        if kind == "prose":
            for row in render_markdown(body, inner).split("\n"):
                gap = " " * max(0, inner - vw(row))
                out.append(paint(CYAN, "│") + " " + row + gap + " " + paint(CYAN, "│"))
        else:
            out.extend(codelines)  # verbatim — copy-paste clean
    out.append(bottom())
    return "\n".join(out)


_TONES = {"cyan": CYAN, "red": RED, "amber": AMBER, "green": GREEN}


def render_notice(title: str, body: str, tone: str = "cyan") -> str:
    """A short framed notice (banner, error, reset) — light inline formatting, no
    block markdown. Same box language as assistant turns."""
    inner = term_width() - 4
    rendered = "\n".join(
        render_runs(ln)
        for line in body.split("\n")
        for ln in wrap_runs(parse_inline(line), inner)
    )
    return _box(title, rendered, _TONES.get(tone, CYAN))


# --- prompt frame -----------------------------------------------------------


def prompt_glyph() -> str:
    """The interactive prompt glyph: the frame's left gutter, then the cyan ❯."""
    return paint(CYAN, "│") + " " + paint(f"{CYAN};{BOLD}", "❯") + " "


def frame_top() -> str:
    return paint(CYAN, "╭" + "─" * max(0, frame_width() - 2) + "╮")


def frame_bottom() -> str:
    return paint(CYAN, "╰" + "─" * max(0, frame_width() - 2) + "╯")


# --- status bar -------------------------------------------------------------
_SPIN = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


def _mmss(ms: float) -> str:
    s = max(0, int(ms // 1000))
    return f"{s // 60}:{s % 60:02d}"


def _out_count(n: int) -> str:
    if n < 1000:
        return str(n)
    k = n / 1000
    return f"{k:.1f}k" if k < 10 else f"{round(k)}k"


def _ktok(n) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "?"
    if n < 1024:
        return str(n)
    k = n / 1024
    return f"{k:.1f}k" if k < 10 else f"{round(k)}k"


def status_bar(
    model: str,
    used,
    window,
    tps,
    approx: bool = False,
    streaming: bool = False,
    elapsed_ms: float = 0,
    chars: int = 0,
    ctx_measured: bool = True,
    ultra: str | None = None,
    frame: bool = False,
) -> str:
    """Full-width strip: ● state · ctx · tps · model. Spinner + timer while
    streaming; ctx shows a ~ prefix when the window is a guess. `frame=True` swaps
    the free-standing caps (╶─ … ─╴) for the prompt frame's corners (╰─ … ─╯)."""
    W = frame_width()
    if streaming:
        spin = _SPIN[int(time.time() * 1000 / 120) % len(_SPIN)]
        dot = paint(CYAN, spin) + paint(f"{CYAN};{BOLD}", f" streaming {_mmss(elapsed_ms)}")
    else:
        dot = paint(SLATE, "○ idle")
    pct = round((used / window) * 100) if (used is not None and window) else None
    ctx_codes = SLATE if pct is None else GREEN
    win = ("~" if ctx_measured is False else "") + _ktok(window)
    ctx_val = "—" if used is None else f"{_ktok(used)}/{win}" + (f" {pct}%" if pct is not None else "")
    ctx = paint(SLATE, "ctx ") + paint(ctx_codes, ctx_val)
    tps_s = paint(SLATE, "— tps") if tps is None else paint(CYAN, f"{'~' if approx else ''}{tps} tps")
    model_s = paint(SLATE, model or "")
    sep = paint(SLATE, " · ")
    lead = (paint(CYAN, "╰") + paint(SLATE, "─ ")) if frame else paint(SLATE, "╶─ ")

    segs = [dot]
    if ultra:
        segs.append(ultra)
    if streaming and (chars or 0) > 0:
        segs.append(paint(SLATE, f"{_out_count(chars)} out"))
    segs.extend([ctx, tps_s, model_s])
    body = sep.join(segs)
    while vw(lead) + vw(body) + 2 > W and len(segs) > 1:
        segs.pop()
        body = sep.join(segs)
    fill = max(0, W - vw(lead) - vw(body) - 2)
    tail = (paint(SLATE, "─" * fill) + paint(CYAN, "╯")) if frame else paint(SLATE, "─" * fill + "╴")
    return lead + body + " " + tail


class Spinner:
    """A liveness indicator while the model generates: a background thread that
    redraws a single status-bar line (spinner + timer + streamed-char count) every
    ~120 ms, so a thinking model — which streams no visible tokens — still reads as
    working rather than hung. Ported from the pi seat's streaming status bar; there
    the bar is pinned under the input line, here it is one self-clearing line.

    Silent when not a colour TTY. stop() erases the line so the boxed reply that
    follows starts clean."""

    def __init__(self, state=None):
        self._state = state
        self._chars = 0
        self._t0 = 0.0
        self._stop = threading.Event()
        self._thread = None
        self._active = COLOR and _TTY

    def add_chars(self, n: int) -> None:
        self._chars += n

    def _model_ctx(self):
        st = self._state
        if st is None:
            return ("", None, None, None)
        return (getattr(st, "model_key", ""), getattr(st, "used", None),
                getattr(st, "window", None), getattr(st, "tps", None))

    def _run(self) -> None:
        while not self._stop.is_set():
            model, used, window, tps = self._model_ctx()
            bar = status_bar(
                model, used, window, tps,
                streaming=True, elapsed_ms=(time.time() - self._t0) * 1000, chars=self._chars,
            )
            sys.stdout.write("\r\x1b[2K" + bar)
            sys.stdout.flush()
            self._stop.wait(0.12)

    def start(self) -> "Spinner":
        if not self._active:
            return self
        self._t0 = time.time()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if not self._active:
            return
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=0.5)
        sys.stdout.write("\r\x1b[2K")
        sys.stdout.flush()
