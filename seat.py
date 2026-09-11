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
    python3 seat.py                          # REPL, default preset (openrouter-free)
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
import urllib.error
import urllib.request

import identity
import models
import tools

HTTP_TIMEOUT = int(os.environ.get("SYGNIF_PY_HTTP_TIMEOUT", "600"))
MAX_TOOL_ITERS = int(os.environ.get("SYGNIF_PY_MAX_ITERS", "12"))
CONFIRM_TOOLS = {"shell", "write_file", "dev_apply_and_test"}  # gated when --confirm / SYGNIF_PY_CONFIRM=1
CLAUDE_BIN = os.environ.get("SYGNIF_PY_CLAUDE_BIN", "claude")
CLAUDE_TIMEOUT = int(os.environ.get("SYGNIF_PY_CLAUDE_TIMEOUT", "300"))

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


def call_model(spec: dict, messages: list[dict]) -> str:
    if spec.get("provider") == "claude-cli":
        return call_claude_cli(spec, messages)
    url = spec["base_url"].rstrip("/") + "/chat/completions"
    payload = json.dumps(
        {
            "model": spec["id"],
            "messages": messages,
            "max_tokens": spec.get("max_tokens", 4096),
            "stream": False,
        }
    ).encode()
    headers = {"Content-Type": "application/json"}
    if spec.get("api_key"):
        headers["Authorization"] = f"Bearer {spec['api_key']}"
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:500]
        return f"[endpoint HTTP {e.code}: {body}]"
    except Exception as e:  # noqa: BLE001
        return f"[endpoint error: {e} — is {spec['base_url']} reachable?]"
    try:
        return data["choices"][0]["message"]["content"] or ""
    except Exception:
        return f"[endpoint: unexpected response shape: {json.dumps(data)[:500]}]"


# --- agent turn -------------------------------------------------------------


def run_turn(spec: dict, messages: list[dict], reg: dict, confirm: bool) -> None:
    for _ in range(MAX_TOOL_ITERS):
        text = call_model(spec, messages)
        call = parse_tool_call(text)
        if not call:
            print(f"\nSYGNIF> {text}\n")
            messages.append({"role": "assistant", "content": text})
            return
        name, args = call
        pre = _FENCE.sub("", text).strip()
        if pre:
            print(f"\nSYGNIF> {pre}")
        print(f"  → {name}({json.dumps(args, ensure_ascii=False)[:200]})")
        if confirm and name in CONFIRM_TOOLS:
            try:
                ans = input("    run this? [y/N] ").strip().lower()
            except EOFError:
                ans = "n"
            if ans not in ("y", "yes"):
                out = "[operator declined this tool call]"
                print("    skipped.")
            else:
                out = tools.run_tool(reg, name, args)
        else:
            out = tools.run_tool(reg, name, args)
        print(f"  ← {out[:800]}{' …' if len(out) > 800 else ''}\n")
        messages.append({"role": "assistant", "content": text})
        messages.append({"role": "tool", "name": name, "content": out})
    print("\nSYGNIF> [reached tool-iteration cap; stopping this turn]\n")
    messages.append(
        {"role": "assistant", "content": "[reached tool-iteration cap for this turn]"}
    )


# --- session setup ----------------------------------------------------------


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
    messages = [{"role": "system", "content": system}]

    def banner():
        if spec.get("provider") == "claude-cli":
            endpoint = "claude CLI (subscription)"
            key = "claude login" if shutil.which(CLAUDE_BIN) else "run: sygnif login"
        else:
            endpoint = spec.get("base_url")
            key = "set" if spec.get("api_key") else ("none" if not spec.get("api_key_env") else f"missing ${spec['api_key_env']}")
        print(
            f"SYGNIF py — preset='{name}' model='{model_key}'({spec['id']}) "
            f"tools=[{', '.join(reg)}] endpoint={endpoint} key={key}"
            f"{' (confirm on)' if confirm else ''}"
        )

    banner()

    if a.prompt:
        messages.append({"role": "user", "content": " ".join(a.prompt)})
        run_turn(spec, messages, reg, confirm)
        return 0

    print("Type a prompt, or /help for commands.")
    while True:
        try:
            line = input("you> ").strip()
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
                print("  /preset <name>  /model <name>  /models  /tools  /reset  /quit")
                continue
            if cmd == "models":
                print("  " + ", ".join(models.list_models(cfg)))
                continue
            if cmd == "tools":
                for tn, ts in reg.items():
                    print(f"  {tn}: {ts.get('desc','').splitlines()[0] if ts.get('desc') else ''}")
                continue
            if cmd == "preset":
                try:
                    name, preset, reg, system = build_session(cfg, arg)
                    model_key = preset.get("model")
                    spec = models.resolve_model(cfg, model_key)
                    messages = [{"role": "system", "content": system}]
                    banner()
                except Exception as e:  # noqa: BLE001
                    print(f"  [preset error: {e}] available: {', '.join(models.list_presets(cfg))}")
                continue
            if cmd == "model":
                model_key = arg
                spec = models.resolve_model(cfg, model_key)
                where = "claude CLI (subscription)" if spec.get("provider") == "claude-cli" else spec.get("base_url")
                print(f"  model -> {model_key} ({spec['id']}) @ {where}")
                continue
            if cmd == "reset":
                messages = [{"role": "system", "content": system}]
                print("  conversation reset")
                continue
            print(f"  [unknown command /{cmd}] /help for the list")
            continue
        messages.append({"role": "user", "content": line})
        run_turn(spec, messages, reg, confirm)
    return 0


if __name__ == "__main__":
    sys.exit(main())
