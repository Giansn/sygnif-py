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
    python3 seat.py doctor                    # health check: seat, models, containers, RPC
    python3 seat.py --preset chat            # REPL, chat preset
    python3 seat.py --model claude "hello"   # one-shot on your Claude subscription
    python3 seat.py --confirm                # confirm before each shell exec

REPL commands: /preset <name>  /model <name>  /models  /tools  /nexus  /reset  /help  /quit
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

import identity
import models
import pentest
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
# Offensive tools that actively touch a target — also gated under --confirm so a live
# scan/exploit against an authorized host still gets a human yes (review P2-7).
OFFENSIVE_TOOLS = {"recon", "nuclei", "wpscan", "dast", "metasploit", "msf", "bruteforce",
                   "crack", "postexploit", "privesc", "wifi_capture", "wifi_crack",
                   "portscan", "netenum", "takeover", "tls_check", "exploit", "c2", "ad", "aitm", "velociraptor",
                   "coerce", "bloodyad", "winrm", "cloudx", "kube", "emulate", "arp"}
CLAUDE_BIN = os.environ.get("SYGNIF_PY_CLAUDE_BIN", "claude")
CLAUDE_TIMEOUT = int(os.environ.get("SYGNIF_PY_CLAUDE_TIMEOUT", "300"))

# First-run onboarding: a marker gates a one-time setup (Claude login + a pentest
# workspace). SYGNIF_PY_FIRSTRUN=0 skips it; delete the marker to run it again.
FIRSTRUN_MARKER = os.path.expanduser(
    os.environ.get("SYGNIF_PY_FIRSTRUN_MARKER", "~/.sygnif/.sygnif-py-initialized")
)
PENTEST_DIR = os.path.expanduser(os.environ.get("SYGNIF_PY_PENTEST_DIR", "~/sygnif-pentest"))
# Common tools a first pentest reaches for — reported present/missing, and (on
# first run, with consent) installed via the host package manager. Kali/Debian
# ships all of these; on other distros we install what the manager knows.
PENTEST_TOOLS = ["nmap", "curl", "dig", "whois", "nc", "nikto", "gobuster", "sqlmap", "hydra", "openssl"]
# binary name -> package name, per manager, when they differ. Unlisted binaries
# install under their own name (true for nmap, nikto, sqlmap, hydra, whois, ...).
_PKG_NAMES = {
    "apt": {"dig": "dnsutils", "nc": "netcat-traditional"},
    "dnf": {"dig": "bind-utils", "nc": "nmap-ncat"},
    "pacman": {"dig": "bind", "nc": "gnu-netcat"},
    "brew": {"dig": "bind", "nc": "netcat"},
}


def _pkg_manager():
    """Detect the host package manager. Returns (name, install_argv, update_argv|None)
    where argv already carries `sudo` when we're not root and sudo exists. None if
    no known manager is present (e.g. bare macOS without Homebrew)."""
    is_root = getattr(os, "geteuid", lambda: 1)() == 0
    sudo = [] if is_root else (["sudo"] if shutil.which("sudo") else [])
    if shutil.which("apt-get"):
        return ("apt", sudo + ["apt-get", "install", "-y"], sudo + ["apt-get", "update"])
    if shutil.which("brew"):  # macOS — brew refuses to run under sudo, so never prefix it
        return ("brew", ["brew", "install"], None)
    if shutil.which("dnf"):
        return ("dnf", sudo + ["dnf", "install", "-y"], None)
    if shutil.which("pacman"):
        return ("pacman", sudo + ["pacman", "-S", "--noconfirm"], None)
    return None


def _install_pentest_tools(missing: list[str]) -> None:
    """Offer to install the missing pentest tools with the host package manager.
    TTY-gated by the caller; skippable; grounded — we re-check with `which` after
    and only report what actually landed. Disable entirely with SYGNIF_PY_INSTALL_TOOLS=0."""
    if os.environ.get("SYGNIF_PY_INSTALL_TOOLS") == "0":
        pix.notice("  tool install skipped (SYGNIF_PY_INSTALL_TOOLS=0).", "yellow")
        return
    mgr = _pkg_manager()
    if not mgr:
        pix.notice("  no known package manager found — install these yourself: " + ", ".join(missing), "yellow")
        return
    name, install_argv, update_argv = mgr
    pkgs = [_PKG_NAMES.get(name, {}).get(t, t) for t in missing]
    pix.notice(f"  {len(missing)} pentest tool(s) missing. Install with {name}?  packages: {', '.join(pkgs)}")
    try:
        ans = input(pix.cyan("  Install now? ") + pix.dim("[Enter = yes, s = skip] ")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        ans = "s"
        print()
    if ans not in ("", "y", "yes"):
        pix.notice("  skipped. Install later with your package manager, or re-run: sygnif", "yellow")
        return
    try:
        if update_argv:
            print(pix.dim("  running: " + " ".join(update_argv) + "\n"))
            subprocess.call(update_argv)
        cmd = install_argv + pkgs
        print(pix.dim("  running: " + " ".join(cmd) + "\n"))
        rc = subprocess.call(cmd)
    except Exception as e:  # noqa: BLE001
        pix.notice(f"  [install failed: {e} — install the tools manually]", "yellow")
        return
    now_have = [t for t in missing if shutil.which(t)]
    still_missing = [t for t in missing if not shutil.which(t)]
    if now_have:
        pix.notice("  installed: " + ", ".join(now_have), "green")
    if still_missing:
        pix.notice(f"  still missing (rc={rc}): " + ", ".join(still_missing) + " — install these manually", "yellow")

_FENCE = re.compile(r"```[a-zA-Z0-9_+.-]*[ \t]*\r?\n?(\{.*?\})\s*```", re.S)


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


# Tool-call dialects vary by model: the canonical SYGNIF shape is
# {"tool": <name>, "args": {...}}, but OpenAI-compatible models (GLM, GPT, …)
# emit {"name","arguments"} or a {"function":{...}} object, sometimes with args
# as a JSON *string*, and weaker models produce almost-JSON (trailing commas,
# single quotes). The parser below accepts all of these. Non-canonical shapes are
# only honoured when the resolved name is a real tool in the registry, so ordinary
# JSON in a reply is never mistaken for a call.
_NAME_KEYS = ("tool", "tool_name", "name")
_ARG_KEYS = ("args", "arguments", "parameters", "params", "input")
_CALLISH = ('"tool"', '"tool_name"', '"name"', '"function"')


def _lenient_loads(s: str):
    """json.loads, then two safe repairs for weaker models: strip trailing commas,
    and promote single quotes ONLY when there are no double quotes to mangle.
    Returns the parsed value, or None."""
    try:
        return json.loads(s)
    except Exception:  # noqa: BLE001
        pass
    t = re.sub(r",\s*([}\]])", r"\1", s)                 # trailing commas
    try:
        return json.loads(t)
    except Exception:  # noqa: BLE001
        pass
    if '"' not in t and "'" in t:                        # single-quoted JSON
        try:
            return json.loads(t.replace("'", '"'))
        except Exception:  # noqa: BLE001
            pass
    return None


def _coerce_args(v):
    """Normalise an args value to a dict: a dict passes through; a JSON string
    (OpenAI-native stringifies arguments) is parsed; anything else becomes {}."""
    if isinstance(v, dict):
        return v
    if isinstance(v, str) and v.strip():
        d = _lenient_loads(v.strip())
        if isinstance(d, dict):
            return d
    return {}


def _extract_call(obj):
    """(name, args, explicit) from a parsed object across the common shapes, or
    None. explicit=True only for the canonical "tool" key (trusted even when the
    name is unknown); other shapes are validated against the registry by the caller."""
    if not isinstance(obj, dict):
        return None
    fn = obj.get("function")                              # OpenAI tool-call object
    if isinstance(fn, dict) and isinstance(fn.get("name"), str) and fn["name"].strip():
        return fn["name"].strip(), _coerce_args(fn.get("arguments") if "arguments" in fn else fn.get("args")), False
    name, explicit = "", False
    for k in _NAME_KEYS:
        v = obj.get(k)
        if isinstance(v, str) and v.strip():
            name, explicit = v.strip(), (k == "tool")
            break
    if not name:
        return None
    args = {}
    for k in _ARG_KEYS:
        if k in obj:
            args = _coerce_args(obj[k])
            break
    return name, args, explicit


def _candidates(text: str):
    seen_spans = []
    for m in _FENCE.finditer(text):
        try:
            body_start = text.index("{", m.start())
        except ValueError:
            continue
        obj = _balanced_obj(text, body_start) or m.group(1)
        seen_spans.append((body_start, body_start + len(obj)))
        yield obj
    # bare objects (no fence): walk each brace-delimited object that looks call-ish.
    # Balancing (not a flat regex) means key order doesn't matter — args-before-tool
    # and nested args are both found. Bounded so a huge reply can't blow up.
    i, tried = 0, 0
    while tried < 60:
        s = text.find("{", i)
        if s == -1:
            break
        i = s + 1
        if any(a <= s < b for a, b in seen_spans):
            continue
        obj = _balanced_obj(text, s)
        if not obj:
            continue
        tried += 1
        if any(k in obj for k in _CALLISH):
            yield obj


def parse_tool_call(text: str, reg=None):
    """Return (name, args) for the first tool call in the text, else None.
    Adaptive across model dialects (see the note above). Non-canonical shapes are
    accepted only when `reg` is None (test/back-compat) or the name is in `reg`."""
    for cand in _candidates(text):
        obj = _lenient_loads(cand)
        if obj is None:
            continue
        ex = _extract_call(obj)
        if not ex:
            continue
        name, args, explicit = ex
        if explicit or reg is None or name in reg:
            return name, args
    return None


def _synth_tool_text(tool_calls) -> str:
    """Render a native OpenAI `tool_calls` array as the seat's fenced ```tool block
    so the normal text loop parses it. Uses the first call."""
    try:
        fn = (tool_calls[0].get("function") or {})
        name = (fn.get("name") or "").strip()
        if name:
            return "```tool\n" + json.dumps({"tool": name, "args": _coerce_args(fn.get("arguments"))}) + "\n```"
    except Exception:  # noqa: BLE001
        pass
    return ""


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


def _http_messages(messages: list[dict]) -> list[dict]:
    """Normalise messages for OpenAI-compatible /chat/completions endpoints.
    The seat drives tools through a TEXT protocol (a tool call is JSON in the
    assistant's text; the result comes back as a role:tool message), so there is
    never a native `tool_calls` field. Strict endpoints (api.openai.com) reject a
    role:tool message that does not answer a preceding tool_calls, so fold each
    tool result into a plain user turn. Lenient providers see the same content."""
    out = []
    for m in messages:
        if m.get("role") == "tool":
            name = m.get("name", "")
            label = f"Tool({name}) result:" if name else "Tool result:"
            out.append({"role": "user", "content": f"{label}\n{m.get('content') or ''}"})
        else:
            out.append(m)
    return out


def _post_chat(spec: dict, messages: list[dict], t0: float) -> tuple[str, dict]:
    """One non-streaming POST. Returns (text, meta); errors come back as text."""
    url = spec["base_url"].rstrip("/") + "/chat/completions"
    payload = json.dumps({
        "model": spec["id"], "messages": _http_messages(messages),
        spec.get("token_param", "max_tokens"): spec.get("max_tokens", 4096),
        "stream": False,
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
        msg = data["choices"][0]["message"]
        text = msg.get("content") or ""
        # a function-calling model may answer via native tool_calls with empty
        # content — fold that back into the fenced protocol the loop understands.
        if not text.strip() and msg.get("tool_calls"):
            text = _synth_tool_text(msg["tool_calls"]) or text
    except Exception:
        return (f"[endpoint: unexpected response shape: {json.dumps(data)[:500]}]",
                _meta(messages, "", None, time.perf_counter() - t0))
    return text, _meta(messages, text, data.get("usage"), time.perf_counter() - t0)


def _stream_chat(spec: dict, messages: list[dict], on_delta, t0: float) -> tuple[str, dict]:
    """Streaming POST parsing SSE lines. Raises on transport/HTTP failure so the
    caller can fall back to a plain request."""
    url = spec["base_url"].rstrip("/") + "/chat/completions"
    payload = json.dumps({
        "model": spec["id"], "messages": _http_messages(messages),
        spec.get("token_param", "max_tokens"): spec.get("max_tokens", 4096),
        "stream": True, "stream_options": {"include_usage": True},
    }).encode()
    headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
    if spec.get("api_key"):
        headers["Authorization"] = f"Bearer {spec['api_key']}"
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    parts: list[str] = []
    tool_frag: dict = {}   # index -> {"name","args"} accumulated native tool_calls
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
                delta = choices[0].get("delta") or {}
                piece = delta.get("content")
                if piece:
                    parts.append(piece)
                    if on_delta:
                        on_delta(piece)
                for tc in (delta.get("tool_calls") or []):
                    slot = tool_frag.setdefault(tc.get("index", 0), {"name": "", "args": ""})
                    fn = tc.get("function") or {}
                    if fn.get("name"):
                        slot["name"] += fn["name"]
                    if fn.get("arguments"):
                        slot["args"] += fn["arguments"]
            if chunk.get("usage"):
                usage = chunk["usage"]
    text = "".join(parts)
    # native tool_calls with no prose content -> render as a fenced block
    if not text.strip() and tool_frag:
        first = tool_frag[min(tool_frag)]
        if first["name"]:
            text = _synth_tool_text([{"function": {"name": first["name"], "arguments": first["args"]}}])
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
    nudged = False
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
        call = parse_tool_call(text, reg)
        if not call:
            # A code fence that didn't parse as a call is almost always a malformed
            # tool call, not a final answer. Nudge once to re-emit clean JSON before
            # treating the reply as prose — one retry, so a real prose answer with a
            # stray fence still gets through.
            if not nudged and _FENCE.search(text):
                nudged = True
                messages.append({"role": "assistant", "content": text})
                messages.append({"role": "user", "content": (
                    "That looked like a tool call but I could not parse it. Re-emit EXACTLY ONE "
                    'fenced ```tool block containing valid JSON {"tool":"<name>","args":{...}} '
                    "and nothing after it. If you meant to answer, reply in plain prose with no code fence.")})
                pix.notice("  [unparseable tool block — asked the model to re-emit]", "yellow")
                continue
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
        if confirm and (name in CONFIRM_TOOLS or name in OFFENSIVE_TOOLS):
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
    # the preset's model key is the active provider; its per-provider identity
    # overlay (if any) is applied on top of the seat's own identity.
    system = identity.build_system(name, preset.get("focus", ""), reg,
                                   provider=preset.get("model"))
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


def _ensure_prereqs(spec: dict) -> None:
    """Offer to install the two external things the seat uses but cannot ship:
    the `claude` CLI (carries the Claude subscription that backs the default
    model) and `tmux` (portals for `nexus`). Opt-in, TTY-gated, grounded — we
    re-check with `which` afterwards and report only what actually landed.
    Skip the whole step with SYGNIF_PY_BOOTSTRAP=0."""
    if os.environ.get("SYGNIF_PY_BOOTSTRAP") == "0":
        return
    mgr = _pkg_manager()

    def _sh(argv: list[str]) -> int:
        print(pix.dim("  running: " + " ".join(argv) + "\n"))
        try:
            return subprocess.call(argv)
        except Exception as e:  # noqa: BLE001
            pix.notice(f"  [failed: {e}]", "yellow")
            return 1

    def _yes(prompt: str) -> bool:
        try:
            return input(pix.cyan("  " + prompt + " ") + pix.dim("[Enter = yes, s = skip] ")).strip().lower() in ("", "y", "yes")
        except (EOFError, KeyboardInterrupt):
            print()
            return False

    # 1. claude CLI — only if the default model actually needs it and it's missing.
    if spec.get("provider") == "claude-cli" and not shutil.which(CLAUDE_BIN):
        pix.notice("  The default model (Claude Fable 5.1) runs on your Claude Pro/Max")
        pix.notice("  subscription via the official `claude` CLI, which isn't installed yet.")
        if _yes("Install the claude CLI now?"):
            if shutil.which("npm"):
                _sh(["npm", "install", "-g", "@anthropic-ai/claude-code"])
            elif shutil.which("curl"):
                # official native installer (no Node needed)
                _sh(["sh", "-c", "curl -fsSL https://claude.ai/install.sh | bash"])
            elif mgr and _yes("npm not found. Install Node.js first (needed for the claude CLI)?"):
                name, install_argv, update_argv = mgr
                if update_argv:
                    _sh(update_argv)
                _sh(install_argv + (["nodejs", "npm"] if name == "apt" else ["nodejs"]))
                if shutil.which("npm"):
                    _sh(["npm", "install", "-g", "@anthropic-ai/claude-code"])
            else:
                pix.notice("  No npm/curl found — install the claude CLI manually: https://claude.com/claude-code", "yellow")
            if shutil.which(CLAUDE_BIN):
                pix.notice("  claude CLI installed.", "green")
            else:
                pix.notice("  claude CLI still not on PATH — you may need to reopen your shell, "
                           "or install it manually: https://claude.com/claude-code", "yellow")
        else:
            pix.notice("  Skipped. Without it, use a keyed model: /model openrouter-free or /model glm", "yellow")

    # 2. tmux — nexus (agent portals) needs it. Nice-to-have, so a light touch.
    if not shutil.which("tmux") and mgr:
        name, install_argv, update_argv = mgr
        pkg = {"apt": "tmux", "dnf": "tmux", "pacman": "tmux", "brew": "tmux"}.get(name, "tmux")
        if _yes(f"Install tmux (for the `nexus` portal board) with {name}?"):
            if update_argv:
                _sh(update_argv)
            _sh(install_argv + [pkg])
            pix.notice("  tmux installed." if shutil.which("tmux") else "  tmux still missing — install it manually later.",
                       "green" if shutil.which("tmux") else "yellow")


def do_first_run(spec: dict) -> None:
    """One-time onboarding, run the first time `sygnif` is launched interactively:
    install the external prerequisites (claude CLI, tmux), log in to the Claude
    subscription that backs the default model (Fable 5.1), then stand up a pentest
    workspace and report which tools are on the box. Gated by FIRSTRUN_MARKER so
    it never nags after the first successful run."""
    print(pix.rule())
    print(pix.cyan(pix.bold("  Welcome to SYGNIF py")) + pix.dim("  ·  first-run setup"))
    print(pix.dim("  This runs once. It installs prerequisites, logs you in, and preps your first pentest."))
    print(pix.rule())

    # 0. External prerequisites the package can't bundle (claude CLI, tmux).
    _ensure_prereqs(spec)

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

    # 3. Provision the FULL Kali pentest toolset (not just a handful of packages).
    #    pentest.install_full_toolset picks the best tier: metapackages on a Kali
    #    host, a persistent `sygnif-kali` container off kalilinux/kali-rolling on
    #    any Docker host, or a curated apt set as a last resort. Grounded + TTY-gated.
    if os.environ.get("SYGNIF_PY_INSTALL_TOOLS") == "0":
        pix.notice("  Kali toolset install skipped (SYGNIF_PY_INSTALL_TOOLS=0).", "yellow")
    else:
        pentest.toolset_status(pix.notice)
        mode = pentest.choose_mode()
        prompt = {
            "host": "  Install the full Kali toolset (metapackages) on this Kali host now?",
            "docker": "  Set up the full Kali toolset in the `sygnif-py-toolbox` Docker container now?",
            "fallback": "  Install a curated pentest tool set with your package manager now?",
        }.get(mode, "  Install the pentest toolset now?")
        pix.notice(prompt)
        try:
            ans = input(pix.cyan("  Proceed? ") + pix.dim("[Enter = yes, s = skip] ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "s"
            print()
        if ans in ("", "y", "yes"):
            pentest.install_full_toolset(pix.notice)
        else:
            pix.notice("  skipped. Run it any time with:  sygnif kali-setup", "yellow")

    print(pix.rule())
    pix.notice("  You're set. Describe your first authorized target and SYGNIF will begin recon.")
    print(pix.rule())
    _mark_firstrun_done()


def _read_version() -> str:
    try:
        return open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION"),
                    encoding="utf-8").read().strip()
    except OSError:
        return "unknown"


def do_version() -> int:
    print("sygnif-py " + _read_version())
    return 0


def do_update() -> int:
    """Pull the newest sygnif-py in place from the dist host and re-install over
    this directory. Your ~/.sygnif overrides (config, secrets) are untouched —
    only the package files here are refreshed."""
    home = os.path.dirname(os.path.abspath(__file__))
    base = os.environ.get(
        "SYGNIF_PY_BASE_URL",
        "https://raw.githubusercontent.com/Giansn/sygnif-py/main/dist")
    before = _read_version()
    pix.notice(f"  updating sygnif-py in {home}", "cyan")
    pix.notice(f"  current: {before}   source: {base}")
    fetch = None
    for c in ("curl", "wget"):
        if shutil.which(c):
            fetch = c
            break
    if not fetch:
        pix.notice("  need curl or wget to update.", "red")
        return 1
    dl = (f"curl -fsSL {base}/install.sh" if fetch == "curl"
          else f"wget -qO- {base}/install.sh")
    # run the installer against THIS home + base; it re-downloads and unpacks.
    cmd = f"SYGNIF_PY_HOME={shlex.quote(home)} SYGNIF_PY_BASE_URL={shlex.quote(base)} sh -c '{dl} | sh'"
    try:
        rc = subprocess.call(["sh", "-c", cmd])
    except Exception as e:  # noqa: BLE001
        pix.notice(f"  update failed: {e}", "red")
        return 1
    after = _read_version()
    if rc != 0:
        pix.notice(f"  update exited {rc}.", "yellow")
        return rc
    if after == before:
        pix.notice(f"  already up to date ({after}).", "green")
    else:
        pix.notice(f"  updated: {before} -> {after}", "green")
    pix.notice("  restart the seat to load the new version.")
    return 0


def do_doctor() -> int:
    """`sygnif doctor` — one-shot health check of the seat and its backends, so
    the operator can verify everything in a line instead of poking by hand.
    Exit 0 if nothing is broken (warnings allowed), 1 if a hard check fails."""
    import shutil
    ok = "✓"; warn = "⚠"; bad = "✗"
    hard_fail = False

    def line(sym, label, detail=""):
        col = "green" if sym == ok else ("yellow" if sym == warn else "red")
        pix.notice(f"  {sym} {label}" + (f"  {detail}" if detail else ""), col)

    pix.notice(pix.rule() if hasattr(pix, "rule") else "")
    pix.notice(pix.cyan(pix.bold("  SYGNIF py doctor")) if hasattr(pix, "cyan") else "SYGNIF py doctor")

    # --- config + presets ---
    try:
        cfg = models.load_config()
        presets = models.list_presets(cfg)
        line(ok, "config + presets", f"{len(presets)} presets: {', '.join(presets)}")
    except Exception as e:  # noqa: BLE001
        line(bad, "config", str(e)[:120]); return 1

    # --- tool registry for every preset ---
    reg_bad = []
    for pn in presets:
        _, pr = models.get_preset(cfg, pn)
        reg = tools.build_registry(pr.get("tools", []))
        missing = [t for t in pr.get("tools", []) if t not in reg]
        if missing:
            reg_bad.append(f"{pn}:{','.join(missing)}")
    if reg_bad:
        line(bad, "tool registry", "missing " + "; ".join(reg_bad)); hard_fail = True
    else:
        line(ok, "tool registry", "all preset tools resolve")

    # --- default model readiness ---
    _, dpreset = models.get_preset(cfg, None)
    mk = dpreset.get("model")
    st, hint = models.model_status(cfg, mk)
    line(ok if st in ("ready", "keyless") else warn, f"default model '{mk}'", f"{st} — {hint}")

    # --- workspace ---
    ws = os.path.expanduser(os.environ.get("SYGNIF_PY_PENTEST_DIR", "~/sygnif-pentest"))
    line(ok if os.path.isdir(ws) else warn, "pentest workspace",
         ws if os.path.isdir(ws) else ws + " (missing — created on first run)")

    # --- Docker toolbox (self-contained; absence is a warning, not a failure) ---
    if not tools._docker_ok():
        line(warn, "docker", "not present — network/offensive tools run on host binaries only")
    else:
        box = tools._toolbox_name()
        if not box:
            line(warn, "toolbox", "none yet — run `sygnif toolbox up` (bare) or "
                 "`sygnif kali-setup` (full toolset)")
        else:
            line(ok, "toolbox", box + " (running)")
            try:
                r = subprocess.run(["docker", "exec", box, "bash", "-lc",
                                    "command -v nmap nuclei wpscan >/dev/null 2>&1 && echo yes || echo no"],
                                   capture_output=True, text=True, timeout=15).stdout.strip()
                line(ok if r == "yes" else warn, "toolset",
                     "core tools present" if r == "yes" else "sparse — run `sygnif kali-setup`")
            except Exception:  # noqa: BLE001
                line(warn, "toolset", "could not probe the toolbox")

    pix.notice("  " + (bad + " doctor: a hard check failed" if hard_fail else ok + " doctor: healthy"),
               "red" if hard_fail else "green")
    return 1 if hard_fail else 0


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "login":
        return do_login()
    if len(sys.argv) >= 2 and sys.argv[1] in ("doctor", "health", "check"):
        return do_doctor()
    if len(sys.argv) >= 2 and sys.argv[1] in ("update", "upgrade", "self-update"):
        return do_update()
    if len(sys.argv) >= 2 and sys.argv[1] in ("version", "--version", "-V"):
        return do_version()
    if len(sys.argv) >= 2 and sys.argv[1] in ("kali-setup", "kali_setup"):
        pentest.toolset_status(pix.notice)
        ok = pentest.install_full_toolset(pix.notice)
        return 0 if ok else 1
    if len(sys.argv) >= 2 and sys.argv[1] == "toolbox":
        # sygnif-py's own Docker pentest toolbox: status | up | rebuild
        sub = sys.argv[2] if len(sys.argv) >= 3 else "status"
        box = tools._toolbox_name(auto_create=(sub == "up"))
        if sub == "status":
            pix.notice(f"  toolbox: {box or '(none — host-only)'}"
                       + (f"  image={tools.TOOLBOX_IMAGE}" if box else ""),
                       "green" if box else "yellow")
            if not box and tools._docker_ok():
                pix.notice("  Docker is present. Provision it with:  sygnif toolbox up   "
                           "(bare) or  sygnif kali-setup  (full toolset).")
            elif not tools._docker_ok():
                pix.notice("  Docker not found — tools fall back to host binaries.", "yellow")
            return 0
        if sub == "up":
            pix.notice(f"  toolbox ready: {box}" if box else "  could not provision (need Docker).",
                       "green" if box else "yellow")
            pix.notice("  add the full toolset with:  sygnif kali-setup")
            return 0 if box else 1
        if sub == "rebuild":
            subprocess.call(["docker", "rm", "-f", tools.TOOLBOX_NAME])
            box = tools._toolbox_name(auto_create=True)
            pix.notice(f"  rebuilt: {box}" if box else "  rebuild failed (need Docker).",
                       "green" if box else "yellow")
            return 0 if box else 1
        pix.notice("  usage: sygnif toolbox [status|up|rebuild]", "yellow")
        return 1
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
    try:
        spec = models.resolve_model(cfg, model_key)
    except ValueError as e:
        pix.notice(f"[sygnif-py] {e}", "red")
        sys.exit(2)

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

    # REPL: full PIX chrome — wordmark, then the Σ SYGNIF seat welcome box (pi parity).
    _wm = pix.banner()
    if _wm:
        print("\n" + _wm + "\n")
    if spec.get("provider") == "claude-cli":
        _key = "claude login" if shutil.which(CLAUDE_BIN) else "run: sygnif login"
    else:
        _key = "set" if spec.get("api_key") else ("none" if not spec.get("api_key_env") else f"missing ${spec['api_key_env']}")
    _switch = " · ".join("/" + k for k in models.list_models(cfg)) + " → switch model"
    pix.seat_box(
        spec["id"], len(reg),
        "presets: " + ", ".join(models.list_presets(cfg)),
        _switch,
        "/reset → new session   /exit (/quit) → leave   Ctrl-C → abort",
        probe=f"{endpoint_of(spec)} · key={_key}" + ("  · confirm on" if confirm else ""),
    )

    while True:
        try:
            line = pix.read_prompt_box(state.model_key, state.used, state.window, state.tps, state.turns).strip()
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
            # Re-read config on every command: cfg is otherwise frozen at launch,
            # so a model edited in config.json / ~/.sygnif/sygnif-py.json while the
            # seat is open would still resolve to its stale spec (e.g. a model
            # repointed from the claude CLI to an HTTP endpoint kept reporting
            # "claude CLI not installed"). Two small JSON reads, once per command.
            cfg = models.load_config()
            if cmd == "help":
                pix.notice("  /preset <name>  /model <name>  /<model>  /models  /tools  /nexus  /reset  /quit")
                continue
            if cmd == "models":
                # Show readiness, not just names: a user shouldn't discover a
                # model needs a login or a key only by trying it. Mark the active.
                _marks = {"ready": "●", "keyless": "○", "needs-key": "!", "needs-login": "!"}
                for _m in models.list_models(cfg):
                    _st, _hint = models.model_status(cfg, _m)
                    _active = "→ " if _m == model_key else "  "
                    pix.notice(f"  {_active}{_marks.get(_st,'?')} {_m:16s} {_st:11s} {_hint}")
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
                try:
                    new_spec = models.resolve_model(cfg, arg)
                except ValueError as e:
                    pix.notice(f"  [{e}]", "red")
                    pix.notice(f"  keeping current model: {model_key}", "yellow")
                    continue
                model_key = arg
                spec = new_spec
                state.set_model(model_key, spec)
                state.used = None
                pix.notice(f"  model -> {model_key} ({spec['id']}) @ {endpoint_of(spec)}")
                continue
            if cmd == "reset":
                messages = [{"role": "system", "content": system}]
                state.used = None
                pix.notice("  conversation reset")
                continue
            if cmd == "nexus":
                # The Nexus from inside the seat: see the portals, open or close
                # one, without leaving the conversation. Attaching stays a
                # terminal action (you cannot nest a TUI inside this one), so we
                # hand back the command to run instead of pretending to attach.
                try:
                    import nexus as _nx  # noqa: PLC0415 — optional module
                except Exception as e:  # noqa: BLE001
                    pix.notice(f"  [nexus unavailable: {e}]", "red")
                    continue
                if not _nx.have_tmux():
                    pix.notice("  nexus needs tmux (portals ARE tmux sessions)", "yellow")
                    continue
                _nx.refresh_types()
                parts = arg.split()
                if not parts:
                    ps = _nx.list_portals()
                    if not ps:
                        pix.notice("  no live portals")
                    for p in ps:
                        dot = "●" if p["state"] == "attached" else "○"
                        pix.notice(f"  {dot} {p['name']:<28} {p['state']:<9} {p['size']}")
                    pix.notice(f"  types: {', '.join(_nx.TYPES)}", "cyan")
                    pix.notice("  /nexus <type> [label] → open · /nexus kill <name> → close")
                elif parts[0] == "kill" and len(parts) > 1:
                    r = _nx.kill_portal(parts[1])
                    pix.notice("  " + (f"killed {parts[1]}" if r.get("ok")
                                       else str(r.get("error"))),
                               "cyan" if r.get("ok") else "red")
                else:
                    r = _nx.create_portal(parts[0], parts[1] if len(parts) > 1 else "main")
                    if r.get("ok"):
                        pix.notice(f"  portal {r['name']} up — attach with: nexus {r['name']}",
                                   "cyan")
                    else:
                        pix.notice("  " + str(r.get("error")), "red")
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
