#!/usr/bin/env python3
"""SYGNIF py — the generic SYGNIF seat.

A small, dependency-free agent loop over ANY OpenAI-compatible chat endpoint.
The model calls tools by emitting a fenced ```tool block; this loop parses it,
runs the tool via tools.py, feeds the result back as a role:tool message, and
repeats until the model answers in prose.

Each model in config.json carries its own base_url and (optional) api_key_env,
so there is no bundled proxy: bring OpenAI, OpenRouter, Ollama, LM Studio, a
local llama.cpp server, or the shipped Inkling bridge — whatever speaks
/v1/chat/completions.

Usage:
    python3 seat.py                          # REPL, default preset (pentest, Fable 5.1)
    python3 seat.py login                    # log in to your Claude subscription
    python3 seat.py --preset chat            # REPL, chat preset
    python3 seat.py --model claude "hello"   # one-shot on your Claude subscription
    python3 seat.py --confirm                # confirm before each shell exec

REPL commands: /preset <name>  /model <name>  /models  /tools  /reset  /help  /quit
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

import identity
import models
import pix
import tools

HTTP_TIMEOUT = int(os.environ.get("SYGNIF_PY_HTTP_TIMEOUT", "600"))
MAX_TOOL_ITERS = int(os.environ.get("SYGNIF_PY_MAX_ITERS", "12"))
# Context compaction (see compact_messages): char budget for the whole history, how
# much recent tool output stays verbatim, how many recent user turns are never
# summarized, and whether the model is asked for a summary (else extractive digest).
HISTORY_BUDGET_CHARS = int(os.environ.get("SYGNIF_PY_HISTORY_BUDGET", "80000"))
HISTORY_TOOL_PROTECT_CHARS = int(os.environ.get("SYGNIF_PY_TOOL_PROTECT", "24000"))
HISTORY_TOOL_HEAD_CHARS = int(os.environ.get("SYGNIF_PY_TOOL_HEAD", "600"))
HISTORY_MSG_HEAD_CHARS = int(os.environ.get("SYGNIF_PY_MSG_HEAD", "1200"))
COMPACT_KEEP_TURNS = int(os.environ.get("SYGNIF_PY_COMPACT_KEEP_TURNS", "4"))
COMPACT_SUMMARY = os.environ.get("SYGNIF_PY_COMPACT_SUMMARY", "1") != "0"
COMPACT_PREFIX = "[Compacted earlier conversation — older turns summarized to free context]\n\n"
CONFIRM_TOOLS = {"shell", "write_file", "dev_apply_and_test"}  # gated when --confirm / SYGNIF_PY_CONFIRM=1
CLAUDE_BIN = os.environ.get("SYGNIF_PY_CLAUDE_BIN", "claude")
CLAUDE_TIMEOUT = int(os.environ.get("SYGNIF_PY_CLAUDE_TIMEOUT", "300"))

# First-run onboarding: a marker gates a one-time setup (Claude login + a pentest
# workspace). SYGNIF_PY_FIRSTRUN=0 skips it; delete the marker to run it again.
FIRSTRUN_MARKER = os.path.expanduser(
    os.environ.get("SYGNIF_PY_FIRSTRUN_MARKER", "~/.sygnif/.sygnif-py-initialized")
)
PENTEST_DIR = os.path.expanduser(os.environ.get("SYGNIF_PY_PENTEST_DIR", "~/sygnif-pentest"))
# Common tools a first pentest reaches for — reported present/missing, never assumed.
PENTEST_TOOLS = ["nmap", "curl", "dig", "whois", "nc", "nikto", "gobuster", "sqlmap", "hydra", "openssl"]

_FENCE = re.compile(r"```(?:tool|json)?\s*(\{.*?\})\s*```", re.S)


# --- tool-call parsing ------------------------------------------------------


def _balanced_obj(text: str, start: int) -> str | None:
    """Return the balanced {...} object beginning at text[start], string-aware."""
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _candidates(text: str):
    seen_spans = []
    for m in _FENCE.finditer(text):
        body_start = text.index("{", m.start())
        obj = _balanced_obj(text, body_start) or m.group(1)
        seen_spans.append((body_start, body_start + len(obj)))
        yield obj
    for m in re.finditer(r'\{[^{}]*"tool"', text):
        s = m.start()
        if any(a <= s < b for a, b in seen_spans):
            continue
        obj = _balanced_obj(text, s)
        if obj:
            yield obj


def parse_tool_call(text: str):
    """Return (name, args) for the first well-formed tool call, else None."""
    for cand in _candidates(text):
        try:
            obj = json.loads(cand)
        except Exception:
            continue
        if isinstance(obj, dict) and "tool" in obj:
            name = str(obj.get("tool", "")).strip()
            args = obj.get("args") or {}
            if not isinstance(args, dict):
                args = {}
            if name:
                return name, args
    return None


# --- transport: Claude subscription via the official claude CLI -------------
# This provider does NOT reimplement Anthropic's OAuth. It shells out to the
# installed `claude` CLI (logged in once via `sygnif login` -> `claude
# setup-token`), exactly like SYGNIF's proven claude_subscription_proxy: because
# the CLI makes the upstream call, usage bills to your Claude Pro/Max plan, not
# the pay-per-use API. The seat still drives its OWN tools via the fenced
# protocol; the CLI is used purely as a text generator here.


def _flatten_content(content) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, str):
                parts.append(b)
            elif isinstance(b, dict) and (
                b.get("type") in ("text", "input_text", "output_text") or "text" in b
            ):
                parts.append(str(b.get("text", "")))
        return "\n".join(p for p in parts if p)
    return str(content)


def _split_messages(messages: list[dict]) -> tuple[str, str]:
    """Split OpenAI-style messages into (system_prompt, transcript) for the CLI."""
    system_chunks, transcript = [], []
    for m in messages:
        role = m.get("role", "user")
        text = _flatten_content(m.get("content"))
        if not text:
            continue
        if role == "system":
            system_chunks.append(text)
        elif role == "assistant":
            transcript.append(f"Assistant: {text}")
        elif role == "tool":
            transcript.append(f"Tool({m.get('name', '')}): {text}")
        else:
            transcript.append(f"User: {text}")
    return "\n\n".join(system_chunks), "\n\n".join(transcript)


def _claude_child_env() -> dict:
    """Strip base-url / API-key overrides so the CLI hits the real Anthropic API
    on the subscription login — never a proxy or the pay-per-use key."""
    env = dict(os.environ)
    for k in (
        "ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL", "ANTHROPIC_BASE",
        "CLAUDE_CODE_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_TOKEN",
    ):
        env.pop(k, None)
    return env


def call_claude_cli(spec: dict, messages: list[dict]) -> str:
    if not shutil.which(CLAUDE_BIN):
        return (
            "[claude CLI not found — install it (https://claude.com/claude-code), "
            "then run `sygnif login`]"
        )
    system, prompt = _split_messages(messages)
    cmd = [
        CLAUDE_BIN, "--print", "--output-format", "json",
        "--no-session-persistence", "--dangerously-skip-permissions",
    ]
    if spec.get("id"):
        cmd += ["--model", str(spec["id"])]
    if system:
        cmd += ["--append-system-prompt", system]
    try:
        proc = subprocess.run(
            cmd, input=prompt, capture_output=True, text=True,
            timeout=CLAUDE_TIMEOUT, env=_claude_child_env(),
        )
    except subprocess.TimeoutExpired:
        return f"[claude CLI timed out after {CLAUDE_TIMEOUT}s]"
    except Exception as e:  # noqa: BLE001
        return f"[claude CLI error: {e}]"
    if proc.returncode != 0:
        err = (proc.stderr or "").strip()[:400]
        low = err.lower()
        if any(w in low for w in ("login", "auth", "subscription", "unauthorized")):
            return f"[claude CLI not logged in — run `sygnif login`. detail: {err}]"
        return f"[claude CLI exit {proc.returncode}: {err}]"
    try:
        data = json.loads(proc.stdout)
        return data.get("result") or ""
    except Exception:  # noqa: BLE001
        return proc.stdout.strip() or "[claude CLI: empty response]"


# --- transport (direct OpenAI-compatible) -----------------------------------

# Streaming is the default over a TTY (live prose, real tps, ctx occupancy from
# usage). It falls back to a single non-streaming request when the endpoint
# rejects the stream or errors, so error text and quirky providers still work.


def _est_tokens(chars: int) -> int:
    return max(1, chars // 4)


def _meta(messages: list[dict], text: str, usage: dict | None, elapsed: float) -> dict:
    """Per-turn readout for the pix info line: token occupancy + throughput.
    Uses server-reported usage when present, else a ~4-chars/token estimate."""
    if usage:
        pt = usage.get("prompt_tokens")
        ct = usage.get("completion_tokens")
        total = usage.get("total_tokens") or ((pt or 0) + (ct or 0))
        measured = True
    else:
        pt = _est_tokens(_history_chars(messages))
        ct = _est_tokens(len(text))
        total = pt + ct
        measured = False
    tps = round(ct / elapsed) if (ct and elapsed > 0) else None
    return {"prompt_tokens": pt, "completion_tokens": ct, "total_tokens": total,
            "tps": tps, "elapsed": elapsed, "measured": measured}


def _post_chat(spec: dict, messages: list[dict], t0: float) -> tuple[str, dict]:
    """One non-streaming POST. Returns (text, meta); errors come back as text."""
    url = spec["base_url"].rstrip("/") + "/chat/completions"
    payload = json.dumps({
        "model": spec["id"], "messages": messages,
        "max_tokens": spec.get("max_tokens", 4096), "stream": False,
    }).encode()
    headers = {"Content-Type": "application/json"}
    if spec.get("api_key"):
        headers["Authorization"] = f"Bearer {spec['api_key']}"
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:500]
        return f"[endpoint HTTP {e.code}: {body}]", _meta(messages, "", None, time.perf_counter() - t0)
    except Exception as e:  # noqa: BLE001
        return (f"[endpoint error: {e} — is {spec['base_url']} reachable?]",
                _meta(messages, "", None, time.perf_counter() - t0))
    try:
        text = data["choices"][0]["message"]["content"] or ""
    except Exception:
        return (f"[endpoint: unexpected response shape: {json.dumps(data)[:500]}]",
                _meta(messages, "", None, time.perf_counter() - t0))
    return text, _meta(messages, text, data.get("usage"), time.perf_counter() - t0)


def _stream_chat(spec: dict, messages: list[dict], on_delta, t0: float) -> tuple[str, dict]:
    """Streaming POST parsing SSE lines. Raises on transport/HTTP failure so the
    caller can fall back to a plain request."""
    url = spec["base_url"].rstrip("/") + "/chat/completions"
    payload = json.dumps({
        "model": spec["id"], "messages": messages,
        "max_tokens": spec.get("max_tokens", 4096),
        "stream": True, "stream_options": {"include_usage": True},
    }).encode()
    headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
    if spec.get("api_key"):
        headers["Authorization"] = f"Bearer {spec['api_key']}"
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    parts: list[str] = []
    usage = None
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        for raw in resp:
            line = raw.decode("utf-8", "replace").strip()
            if not line or not line.startswith("data:"):
                continue
            chunk_s = line[5:].strip()
            if chunk_s == "[DONE]":
                break
            try:
                chunk = json.loads(chunk_s)
            except Exception:  # noqa: BLE001
                continue
            choices = chunk.get("choices") or []
            if choices:
                piece = (choices[0].get("delta") or {}).get("content")
                if piece:
                    parts.append(piece)
                    if on_delta:
                        on_delta(piece)
            if chunk.get("usage"):
                usage = chunk["usage"]
    text = "".join(parts)
    return text, _meta(messages, text, usage, time.perf_counter() - t0)


def call_model_stream(spec: dict, messages: list[dict], on_delta=None) -> tuple[str, dict]:
    """Model call for the REPL turn. Streams (with live on_delta) when possible,
    returning (text, meta) where meta drives the pix info line."""
    t0 = time.perf_counter()
    if spec.get("provider") == "claude-cli":
        text = call_claude_cli(spec, messages)  # no token stream; emit whole
        if on_delta and text:
            on_delta(text)
        return text, _meta(messages, text, None, time.perf_counter() - t0)
    if on_delta is not None:
        try:
            return _stream_chat(spec, messages, on_delta, t0)
        except Exception:  # noqa: BLE001 — endpoint rejected stream; fall back
            pass
    return _post_chat(spec, messages, t0)


def call_model(spec: dict, messages: list[dict]) -> str:
    """Plain-text call (used by the compaction summarizer). Non-streaming."""
    return call_model_stream(spec, messages)[0]


# --- context compaction -----------------------------------------------------
#
# Without this the history only ever grew: a long session, or one tool-heavy turn,
# walked straight into the provider's context limit and the turn died. Three tiers,
# applied IN PLACE before every model call (turn start AND between tool rounds):
#   1. mechanical — old tool outputs collapse to a head + marker; the most recent
#      HISTORY_TOOL_PROTECT_CHARS of tool output stay verbatim (ported from the Desk).
#   2. summary — still over budget: everything older than the last COMPACT_KEEP_TURNS
#      user turns becomes ONE structured summary written by the SAME model/CLI the seat
#      already talks to (incremental: a previous summary is updated, not re-summarized).
#      If the model call fails, a model-free extractive digest stands in.
#   3. backstop — still over budget: head-truncate older turns, newest first.
# /reset still clears everything; this only keeps a session alive between resets.

COMPACT_INSTRUCTIONS = (
    "You are compacting the SYGNIF agent's working memory so it can continue the SAME task "
    "in a fresh context with NO loss. Write ONE dense, structured summary with sections: "
    "1. Goal  2. Architecture & key concepts  3. Files & exact paths touched (real only)  "
    "4. Commands run and their REAL results  5. Errors and fixes  6. Decisions and why  "
    "7. Open threads  8. Current work + exact next step. "
    "If a <previous-summary> is given, UPDATE it with the new turns instead of starting over. "
    "Be terse but lossless on task-critical facts. Output ONLY the summary."
)


def _history_chars(messages: list[dict]) -> int:
    return sum(len(m.get("content") or "") for m in messages)


def _collapse_tool_outputs(body: list[dict]) -> tuple[list[dict], int, int]:
    """Tier 1. Returns (new_body, collapsed_count, freed_chars). Pure."""
    hits = [i for i, m in enumerate(body) if m.get("role") == "tool" and isinstance(m.get("content"), str)]
    protected, running = set(), 0
    for i in reversed(hits):
        if running >= HISTORY_TOOL_PROTECT_CHARS:
            break
        protected.add(i)
        running += len(body[i]["content"])
    out, collapsed, freed = list(body), 0, 0
    for i in hits:
        if i in protected:
            continue
        c = body[i]["content"]
        if "[collapsed: " in c or len(c) <= HISTORY_TOOL_HEAD_CHARS + 120:
            continue
        repl = c[:HISTORY_TOOL_HEAD_CHARS] + (
            f"\n[collapsed: {len(c) - HISTORY_TOOL_HEAD_CHARS} further chars of "
            f"{body[i].get('name', 'tool')} output — re-run the tool if you need it]")
        out[i] = {**body[i], "content": repl}
        collapsed += 1
        freed += len(c) - len(repl)
    return out, collapsed, freed


def _extractive_digest(older: list[dict], max_chars: int = 6000) -> str:
    """Model-free fallback: asks + answers (heads), tool calls as names; results dropped."""
    lines = []
    for m in older:
        c = (m.get("content") or "").strip()
        role = m.get("role")
        if role == "user":
            lines.append("User: " + " ".join(c.split())[:500])
        elif role == "assistant":
            head = _FENCE.sub("", c).strip()
            if head:
                lines.append("Assistant: " + " ".join(head.split())[:500])
            call = parse_tool_call(c)
            if call:
                lines.append(f"  tool {call[0]}({json.dumps(call[1], ensure_ascii=False)[:160]})")
    kept, total = [], 0
    for ln in reversed(lines):  # newest survive a tight budget
        if total + len(ln) + 1 > max_chars:
            break
        kept.append(ln)
        total += len(ln) + 1
    kept.reverse()
    dropped = len(lines) - len(kept)
    return (
        "[Mechanical extractive digest — the model summary was unavailable at compaction time.]"
        + (f"\n[{dropped} older lines omitted]" if dropped else "")
        + "\n\n" + "\n".join(kept)
    )


def _summarize_older(spec: dict, older: list[dict], previous: str | None) -> str | None:
    """Tier 2 via the seat's own transport. None when the call failed (caller falls back)."""
    parts = []
    if previous:
        parts.append(f"<previous-summary>\n{previous}\n</previous-summary>\n")
    parts.append("<conversation>")
    for m in older:
        parts.append(f"[{m.get('role')}{(' ' + m['name']) if m.get('name') else ''}]\n{m.get('content') or ''}")
    parts.append("</conversation>")
    text = call_model(spec, [
        {"role": "system", "content": COMPACT_INSTRUCTIONS},
        {"role": "user", "content": "\n\n".join(parts)},
    ])
    text = (text or "").strip()
    if not text or (text.startswith("[") and text.endswith("]") and any(
            w in text.lower() for w in ("error", "http ", "timed out", "not found", "not logged in", "exit "))):
        return None
    return text


def compact_messages(spec: dict, messages: list[dict], notify=print) -> bool:
    """Compact `messages` IN PLACE when over HISTORY_BUDGET_CHARS. Returns True if changed.
    Never raises — a compaction failure must not kill the turn."""
    try:
        if _history_chars(messages) <= HISTORY_BUDGET_CHARS:
            return False
        system = messages[0] if messages and messages[0].get("role") == "system" else None
        sys_chars = len(system["content"]) if system else 0
        body = messages[1:] if system else list(messages)
        budget = HISTORY_BUDGET_CHARS - sys_chars
        body, collapsed, freed = _collapse_tool_outputs(body)
        how = [f"collapsed {collapsed} tool outputs"] if collapsed else []
        if _history_chars(body) > budget:
            user_idx = [i for i, m in enumerate(body)
                        if m.get("role") == "user" and not (m.get("content") or "").startswith(COMPACT_PREFIX)]
            if len(user_idx) > COMPACT_KEEP_TURNS:
                cut = user_idx[-COMPACT_KEEP_TURNS]
                older, recent = body[:cut], body[cut:]
                previous = None
                if older and older[0].get("role") == "user" and (older[0].get("content") or "").startswith(COMPACT_PREFIX):
                    previous = older[0]["content"][len(COMPACT_PREFIX):]
                    older = older[1:]
                summary = _summarize_older(spec, older, previous) if COMPACT_SUMMARY else None
                mode = "model summary"
                if summary is None:
                    summary = ((previous + "\n\n---\n\n") if previous else "") + _extractive_digest(older)
                    mode = "extractive digest (model summary unavailable)"
                body = [{"role": "user", "content": COMPACT_PREFIX + summary}] + recent
                how.append(f"{len(older)} older msgs → {mode}" + (" (updated previous)" if previous else ""))
        if _history_chars(body) > budget:  # backstop, ported from the Desk
            running, cut_n = 0, 0
            for i in range(len(body) - 1, -1, -1):
                c = body[i].get("content") or ""
                if running + len(c) <= budget or i == len(body) - 1 or len(c) <= HISTORY_MSG_HEAD_CHARS + 80:
                    running += len(c)
                    continue
                head = c[:HISTORY_MSG_HEAD_CHARS]
                body[i] = {**body[i], "content": head + f"\n\n[older turn truncated: {len(c) - len(head)} further chars]"}
                running += len(body[i]["content"])
                cut_n += 1
            if cut_n:
                how.append(f"truncated {cut_n} older turns")
        before = _history_chars(messages)
        messages[:] = ([system] if system else []) + body
        notify(f"  [context compacted: {before} → {_history_chars(messages)} chars — {'; '.join(how)}]")
        return True
    except Exception as e:  # noqa: BLE001
        notify(f"  [compaction skipped: {e}]")
        return False


# --- agent turn -------------------------------------------------------------


def run_turn(spec: dict, messages: list[dict], reg: dict, confirm: bool, state=None) -> None:
    for _ in range(MAX_TOOL_ITERS):
        compact_messages(spec, messages, notify=pix.notice)  # turn start AND between rounds
        if pix.PIX:
            live = pix.LiveText(on_first=pix.reply_header)
            text, meta = call_model_stream(spec, messages, live.feed)
            live.close()
        else:
            text, meta = call_model_stream(spec, messages)
        if state is not None:
            state.update(spec, meta)
        call = parse_tool_call(text)
        if not call:
            if not pix.PIX:
                print(f"\nSYGNIF> {text}\n")
            messages.append({"role": "assistant", "content": text})
            return
        name, args = call
        if not pix.PIX:
            pre = _FENCE.sub("", text).strip()
            if pre:
                print(f"\nSYGNIF> {pre}")
        pix.tool_start(name, json.dumps(args, ensure_ascii=False)[:200])
        if confirm and name in CONFIRM_TOOLS:
            try:
                ans = input(pix.dim("    run this? [y/N] ")).strip().lower()
            except EOFError:
                ans = "n"
            out = tools.run_tool(reg, name, args) if ans in ("y", "yes") else "[operator declined this tool call]"
        else:
            out = tools.run_tool(reg, name, args)
        preview = out[:800] + (" …" if len(out) > 800 else "")
        pix.tool_end(preview, is_error=out.lstrip().startswith("[operator declined"))
        messages.append({"role": "assistant", "content": text})
        messages.append({"role": "tool", "name": name, "content": out})
    pix.notice("[reached tool-iteration cap; stopping this turn]", "yellow")
    messages.append(
        {"role": "assistant", "content": "[reached tool-iteration cap for this turn]"}
    )


# --- session setup ----------------------------------------------------------


class SessionState:
    """What the pix info line reports: current model, context window and last
    measured occupancy/throughput, and how many turns have run."""

    def __init__(self):
        self.turns = 0
        self.model_key = ""
        self.window = None
        self.used = None
        self.tps = None

    def set_model(self, model_key: str, spec: dict) -> None:
        self.model_key = model_key
        self.window = spec.get("context")

    def update(self, spec: dict, meta: dict) -> None:
        self.window = spec.get("context") or self.window
        if meta.get("total_tokens"):
            self.used = meta["total_tokens"]
        if meta.get("tps") is not None:
            self.tps = meta["tps"]


def build_session(cfg: dict, preset_name: str | None):
    name, preset = models.get_preset(cfg, preset_name)
    reg = tools.build_registry(preset.get("tools", models.DEFAULT_TOOLS))
    system = identity.build_system(name, preset.get("focus", ""), reg)
    return name, preset, reg, system


def do_login() -> int:
    """`sygnif login` — authenticate your Claude subscription via the official
    claude CLI (wraps `claude setup-token`). One-time; the token is stored by the
    CLI itself, not by SYGNIF py."""
    if not shutil.which(CLAUDE_BIN):
        print("SYGNIF py — Claude subscription login\n")
        print("The official Claude CLI is not installed. Install it first:")
        print("  https://claude.com/claude-code")
        print("then re-run:  sygnif login")
        return 1
    print("SYGNIF py — logging in to your Claude subscription via the claude CLI.")
    print(f"  running: {CLAUDE_BIN} setup-token\n")
    try:
        rc = subprocess.call([CLAUDE_BIN, "setup-token"])
    except Exception as e:  # noqa: BLE001
        print(f"[login failed: {e}]")
        return 1
    if rc == 0:
        print('\nLogged in. Use your subscription with:  sygnif --model claude "..."')
        print('or set {"default_preset":"...","models":{...}} in ~/.sygnif/sygnif-py.json.')
    return rc


def _firstrun_pending() -> bool:
    """True when the one-time onboarding has not run yet and we're interactive.
    Skipped for one-shot prompts, non-TTY runs, and when SYGNIF_PY_FIRSTRUN=0."""
    if os.environ.get("SYGNIF_PY_FIRSTRUN", "1") == "0":
        return False
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return False
    return not os.path.exists(FIRSTRUN_MARKER)


def _mark_firstrun_done() -> None:
    try:
        os.makedirs(os.path.dirname(FIRSTRUN_MARKER), exist_ok=True)
        with open(FIRSTRUN_MARKER, "w", encoding="utf-8") as fh:
            fh.write(time.strftime("%Y-%m-%dT%H:%M:%S") + "\n")
    except Exception:  # noqa: BLE001
        pass


def do_first_run(spec: dict) -> None:
    """One-time onboarding, run the first time `sygnif` is launched interactively:
    log in to the Claude subscription that backs the default model (Fable 5.1),
    then stand up a pentest workspace and report which tools are on the box. Gated
    by FIRSTRUN_MARKER so it never nags after the first successful run."""
    print(pix.rule())
    print(pix.cyan(pix.bold("  Welcome to SYGNIF py")) + pix.dim("  ·  first-run setup"))
    print(pix.dim("  This runs once. It logs you in and preps your first pentest."))
    print(pix.rule())

    # 1. Claude subscription login (only if the default model is subscription-backed).
    if spec.get("provider") == "claude-cli":
        if shutil.which(CLAUDE_BIN):
            pix.notice(f"  Default model is Claude Fable 5.1 via your Claude Pro/Max subscription ({spec.get('id')}).")
            try:
                ans = input(pix.cyan("  Log in now? ") + pix.dim("[Enter = yes, s = skip] ")).strip().lower()
            except (EOFError, KeyboardInterrupt):
                ans = "s"
                print()
            if ans in ("", "y", "yes"):
                print(pix.dim(f"  running: {CLAUDE_BIN} setup-token\n"))
                try:
                    rc = subprocess.call([CLAUDE_BIN, "setup-token"])
                    pix.notice("  logged in." if rc == 0 else f"  [login exited {rc} — you can retry later with `sygnif login`]",
                               "green" if rc == 0 else "yellow")
                except Exception as e:  # noqa: BLE001
                    pix.notice(f"  [login failed: {e} — retry later with `sygnif login`]", "yellow")
            else:
                pix.notice("  skipped. Run `sygnif login` before using Fable 5.1, or `/model openrouter-free`.", "yellow")
        else:
            pix.notice("  The official Claude CLI is not installed, so Fable 5.1 can't run yet.", "yellow")
            pix.notice("  Install it: https://claude.com/claude-code   then run: sygnif login")
            pix.notice("  Meanwhile you can use a free model with: /model openrouter-free  (needs OPENROUTER_API_KEY)")

    # 2. Pentest workspace + a scope reminder.
    try:
        os.makedirs(PENTEST_DIR, exist_ok=True)
        scope = os.path.join(PENTEST_DIR, "SCOPE.md")
        if not os.path.exists(scope):
            with open(scope, "w", encoding="utf-8") as fh:
                fh.write(
                    "# Pentest scope\n\n"
                    "SYGNIF only tests systems you are AUTHORIZED to test. Before you start,\n"
                    "record here who authorized this, the exact in-scope targets, and the\n"
                    "rules of engagement.\n\n"
                    "- Authorization / owner:\n"
                    "- In-scope targets (hosts / IPs / URLs):\n"
                    "- Out of scope:\n"
                    "- Rules of engagement / time window:\n"
                )
        pix.notice(f"  Pentest workspace ready: {PENTEST_DIR}  (edit SCOPE.md before you start)", "green")
    except Exception as e:  # noqa: BLE001
        pix.notice(f"  [could not create pentest workspace: {e}]", "yellow")

    # 3. Report which pentest tools are actually installed — grounded, not assumed.
    have = [t for t in PENTEST_TOOLS if shutil.which(t)]
    missing = [t for t in PENTEST_TOOLS if not shutil.which(t)]
    pix.notice("  tools present: " + (", ".join(have) if have else "none of the usual set"))
    if missing:
        pix.notice("  not installed: " + ", ".join(missing))

    print(pix.rule())
    pix.notice("  You're set. Describe your first authorized target and SYGNIF will begin recon.")
    print(pix.rule())
    _mark_firstrun_done()


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "login":
        return do_login()
    ap = argparse.ArgumentParser(description="SYGNIF py — the generic SYGNIF seat")
    ap.add_argument("--preset", default=None, help="preset name (default: config default_preset)")
    ap.add_argument("--model", default=None, help="override model (a key in the models table)")
    ap.add_argument("--confirm", action="store_true", help="confirm before each shell/write_file exec")
    ap.add_argument("prompt", nargs="*", help="one-shot prompt; omit for REPL")
    a = ap.parse_args()

    confirm = a.confirm or os.environ.get("SYGNIF_PY_CONFIRM") == "1"
    cfg = models.load_config()
    name, preset, reg, system = build_session(cfg, a.preset)
    model_key = a.model or preset.get("model")
    spec = models.resolve_model(cfg, model_key)

    # First interactive launch after install: log in + prep the pentest workspace.
    if not a.prompt and _firstrun_pending():
        do_first_run(spec)

    messages = [{"role": "system", "content": system}]

    def endpoint_of(sp: dict) -> str:
        return "claude CLI (subscription)" if sp.get("provider") == "claude-cli" else (sp.get("base_url") or "")

    def banner():
        if spec.get("provider") == "claude-cli":
            key = "claude login" if shutil.which(CLAUDE_BIN) else "run: sygnif login"
        else:
            key = "set" if spec.get("api_key") else ("none" if not spec.get("api_key_env") else f"missing ${spec['api_key_env']}")
        pix.hello(name, model_key, spec["id"], endpoint_of(spec))
        pix.banner_line(
            f"  preset='{name}' tools=[{', '.join(reg)}] key={key}"
            f"{' · confirm on' if confirm else ''}"
        )

    state = SessionState()
    state.set_model(model_key, spec)

    if a.prompt:
        banner()
        messages.append({"role": "user", "content": " ".join(a.prompt)})
        run_turn(spec, messages, reg, confirm, state)
        return 0

    # REPL: full PIX chrome — wordmark, then the Σ SYGNIF seat welcome box.
    _wm = pix.banner()
    if _wm:
        print(_wm)
    _switch = " · ".join("/" + k for k in models.list_models(cfg)) + "  → switch model"
    pix.seat_box(
        spec["id"], len(reg),
        "presets: " + ", ".join(models.list_presets(cfg)),
        _switch,
        "/reset → new session   /exit (/quit) → leave   Ctrl-C → abort",
    )
    if spec.get("provider") == "claude-cli":
        _key = "claude login" if shutil.which(CLAUDE_BIN) else "run: sygnif login"
    else:
        _key = "set" if spec.get("api_key") else ("none" if not spec.get("api_key_env") else f"missing ${spec['api_key_env']}")
    pix.banner_line(f"  preset '{name}'  ·  {endpoint_of(spec)}  ·  key={_key}" + ("  ·  confirm on" if confirm else ""))

    while True:
        pix.status_line(state.model_key, state.used, state.window, state.tps, state.turns)
        try:
            line = input(pix.prompt_str()).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not line:
            continue
        if line.startswith("/"):
            cmd, _, arg = line[1:].partition(" ")
            arg = arg.strip()
            if cmd in ("quit", "q", "exit"):
                return 0
            if cmd == "help":
                pix.notice("  /preset <name>  /model <name>  /<model>  /models  /tools  /reset  /quit")
                continue
            if cmd == "models":
                pix.notice("  " + ", ".join(models.list_models(cfg)))
                continue
            if cmd == "tools":
                for tn, ts in reg.items():
                    pix.notice(f"  {tn}: {ts.get('desc','').splitlines()[0] if ts.get('desc') else ''}")
                continue
            if cmd == "preset":
                try:
                    name, preset, reg, system = build_session(cfg, arg)
                    model_key = preset.get("model")
                    spec = models.resolve_model(cfg, model_key)
                    messages = [{"role": "system", "content": system}]
                    state.set_model(model_key, spec)
                    state.used = None
                    banner()
                except Exception as e:  # noqa: BLE001
                    pix.notice(f"  [preset error: {e}] available: {', '.join(models.list_presets(cfg))}", "red")
                continue
            if cmd == "model":
                model_key = arg
                spec = models.resolve_model(cfg, model_key)
                state.set_model(model_key, spec)
                state.used = None
                pix.notice(f"  model -> {model_key} ({spec['id']}) @ {endpoint_of(spec)}")
                continue
            if cmd == "reset":
                messages = [{"role": "system", "content": system}]
                state.used = None
                pix.notice("  conversation reset")
                continue
            if cmd in models.list_models(cfg):
                model_key = cmd
                spec = models.resolve_model(cfg, model_key)
                state.set_model(model_key, spec)
                state.used = None
                pix.notice(f"  model → {model_key} ({spec['id']}) @ {endpoint_of(spec)}", "cyan")
                continue
            pix.notice(f"  [unknown command /{cmd}] /help for the list", "red")
            continue
        state.turns += 1
        pix.turn_separator(state.turns)
        messages.append({"role": "user", "content": line})
        run_turn(spec, messages, reg, confirm, state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
