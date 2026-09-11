#!/usr/bin/env python3
"""SYGNIF Desk — the browser dashboard of SYGNIF py. Python stdlib only.

A "desktop app in the browser" for chat + workflows over the models configured
in sygnif-py (config.json + ~/.sygnif/sygnif-py.json). Serves the static SPA
from ./static and persists all state as JSON files under ~/.sygnif/desk.

Runs on http.server so it installs with zero dependencies:

  * providers          = the sygnif-py model registry (each model key is a
                         provider in the picker; probed via GET /models)
  * chat               = detached streaming generation: the reply keeps
                         generating server-side even if the tab closes; the
                         browser streams by TAILING a buffer and can re-attach
  * exec bridge        = optional ```exec fenced protocol giving the model a
                         LOCAL shell (default OFF: SYGNIF_DESK_EXEC=1),
                         guarded by a blocklist + audit log
  * workflows          = multi-step prompt chains ({{input}}/{{prev}})
  * uploads            = files attach as text when they decode as UTF-8;
                         binary files are stored and referenced (no OCR/audio
                         transcription in the stdlib desk)

Run:  python3 desk.py            (or the `sygnif-desk` launcher)
Env:  SYGNIF_DESK_PORT (8899)  SYGNIF_DESK_HOST (127.0.0.1)
      SYGNIF_DESK_DATA (~/.sygnif/desk)  SYGNIF_DESK_EXEC (off)
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_DIR)

import models  # noqa: E402
import seat  # noqa: E402

STATIC_DIR = os.path.join(APP_DIR, "static")
DATA_DIR = os.path.expanduser(os.environ.get("SYGNIF_DESK_DATA", "~/.sygnif/desk"))
CONV_DIR = os.path.join(DATA_DIR, "conversations")
WF_DIR = os.path.join(DATA_DIR, "workflows")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
for _d in (DATA_DIR, CONV_DIR, WF_DIR, UPLOAD_DIR):
    os.makedirs(_d, exist_ok=True)

HOST = os.environ.get("SYGNIF_DESK_HOST", "127.0.0.1")
PORT = int(os.environ.get("SYGNIF_DESK_PORT", "8899"))
HEALTH_TIMEOUT = 2.5
CHAT_TIMEOUT = int(os.environ.get("SYGNIF_DESK_CHAT_TIMEOUT", "600"))
MAX_UPLOAD = 25 * 1024 * 1024

# --- exec bridge (optional, default OFF) -------------------------------------
EXEC_ENABLED = os.environ.get("SYGNIF_DESK_EXEC", "").strip().lower() in ("1", "true", "yes")
EXEC_MAX_ROUNDS = max(1, int(os.environ.get("SYGNIF_DESK_EXEC_MAX_ROUNDS", "12")))
EXEC_LOOP_BUDGET_S = max(60, int(os.environ.get("SYGNIF_DESK_EXEC_LOOP_BUDGET_S", "900")))
EXEC_TIMEOUT_S = min(120, max(1, int(os.environ.get("SYGNIF_DESK_EXEC_TIMEOUT_S", "30"))))
EXEC_MAX_OUTPUT = max(500, int(os.environ.get("SYGNIF_DESK_EXEC_MAX_OUTPUT", "8000")))
AUDIT_PATH = os.path.join(DATA_DIR, "exec-audit.jsonl")

HISTORY_BUDGET_CHARS = max(20000, int(os.environ.get("SYGNIF_DESK_HISTORY_BUDGET", "80000")))
HISTORY_EXEC_PROTECT_CHARS = max(2000, int(os.environ.get("SYGNIF_DESK_EXEC_PROTECT", "24000")))
HISTORY_EXEC_HEAD_CHARS = max(0, int(os.environ.get("SYGNIF_DESK_EXEC_HEAD", "200")))
HISTORY_MSG_HEAD_CHARS = max(200, int(os.environ.get("SYGNIF_DESK_MSG_HEAD", "1200")))

EXEC_SYSTEM_PROMPT = (
    "You have shell access to the local host machine through an exec bridge. "
    "To run a command, output a fenced block exactly like:\n"
    "```exec\n<one non-interactive shell command>\n```\n"
    "The host executes it and returns the exit code plus stdout/stderr. "
    "Rules: one command per block; wait for each result before continuing; never fabricate "
    "output; prefer precise read-only commands."
)

_EXEC_FENCE_RE = re.compile(r"(?:```|~~~)[ \t]*exec[ \t]*\r?\n(.*?)\r?\n?[ \t]*(?:```|~~~)", re.S)

_EXEC_BLOCKLIST = [
    ("rm-recursive-root", re.compile(r"rm\s+[^|;&]*\s+(?:/|/\*|~(?:/|\b))", re.I)),
    ("mkfs", re.compile(r"\bmkfs", re.I)),
    ("dd-of-device", re.compile(r"\bdd\b[^|;&]*of=/dev/", re.I)),
    ("fork-bomb", re.compile(r":\(\)\{\s*:\|:&\s*\};:", re.S)),
    ("power-control", re.compile(r"\b(?:shutdown|reboot|halt|poweroff)\b|\binit\s+[06]\b", re.I)),
    ("chmod-777-root", re.compile(r"chmod\s+-R\s+777\s+/", re.I)),
    ("write-blockdev", re.compile(r">\s*/dev/(sd|nvme|hd)", re.I)),
]

BUILTIN_WORKFLOWS = [
    {
        "id": "wf-summarize-actions",
        "name": "Summarize -> Extract actions",
        "steps": [
            {"name": "Summarize", "provider": "",
             "prompt": "Summarize the following concisely:\n\n{{input}}"},
            {"name": "Extract actions", "provider": "",
             "prompt": "From this summary, list concrete action items as bullets:\n\n{{prev}}"},
        ],
    },
    {
        "id": "wf-translate-polish",
        "name": "Translate -> polish",
        "steps": [
            {"name": "Translate", "provider": "",
             "prompt": "Translate this text to English:\n\n{{input}}"},
            {"name": "Polish", "provider": "",
             "prompt": "Polish this English text for clarity and tone:\n\n{{prev}}"},
        ],
    },
]


# --------------------------------------------------------------------------
# JSON file helpers
# --------------------------------------------------------------------------
def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _conv_path(cid):
    return os.path.join(CONV_DIR, f"{cid}.json")


def _wf_path(wid):
    return os.path.join(WF_DIR, f"{wid}.json")


def _seed_workflows():
    for wf in BUILTIN_WORKFLOWS:
        path = _wf_path(wf["id"])
        if not os.path.exists(path):
            _write_json(path, wf)


# --------------------------------------------------------------------------
# Providers = the sygnif-py model registry
# --------------------------------------------------------------------------
def _cfg():
    return models.load_config()


def _provider_entry(cfg, key):
    spec = models.resolve_model(cfg, key)
    is_cli = spec.get("provider") == "claude-cli"
    entry = {
        "id": key,
        "label": f"{key} · {spec.get('id', '')}",
        "base_url": "claude CLI (subscription)" if is_cli else spec.get("base_url"),
        "model": spec.get("id"),
        "reachable": False,
        "models": [],
    }
    if is_cli:
        if shutil.which(seat.CLAUDE_BIN):
            entry["reachable"] = True
        else:
            entry["error"] = "claude CLI not installed — run `sygnif login` after installing it"
        return entry
    url = (spec.get("base_url") or "").rstrip("/") + "/models"
    headers = {}
    if spec.get("api_key"):
        headers["Authorization"] = f"Bearer {spec['api_key']}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=HEALTH_TIMEOUT) as resp:
            if resp.status == 200:
                entry["reachable"] = True
                try:
                    data = json.loads(resp.read().decode()).get("data", [])
                    entry["models"] = [
                        m.get("id") for m in data if isinstance(m, dict) and m.get("id")
                    ]
                except Exception as exc:  # noqa: BLE001
                    entry["error"] = f"parse: {exc}"
            else:
                entry["error"] = f"HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        # An auth error still proves the endpoint is alive — reachable, key missing.
        if exc.code in (401, 403):
            entry["reachable"] = True
            env = spec.get("api_key_env")
            entry["error"] = f"HTTP {exc.code}" + (f" — set ${env}" if env and not spec.get("api_key") else "")
        else:
            entry["error"] = f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001
        entry["error"] = str(exc)[:200]
    return entry


def api_providers():
    cfg = _cfg()
    return [_provider_entry(cfg, key) for key in models.list_models(cfg)]


def _resolve(provider_id):
    cfg = _cfg()
    if provider_id not in models.list_models(cfg):
        raise ApiError(400, f"unknown provider: {provider_id}")
    return models.resolve_model(cfg, provider_id)


# --------------------------------------------------------------------------
# Chat plumbing
# --------------------------------------------------------------------------
class ApiError(Exception):
    def __init__(self, status, detail):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _build_messages(messages, system):
    msgs = list(messages or [])
    if system:
        msgs = [{"role": "system", "content": system}] + msgs
    return msgs


def _sse(obj):
    return "data: " + json.dumps(obj, ensure_ascii=False) + "\n\n"


def _extract_delta(obj):
    d = None
    ch = obj.get("choices")
    if isinstance(ch, list) and ch:
        d = ch[0].get("delta")
    elif isinstance(obj.get("delta"), dict):
        d = obj["delta"]
    if not isinstance(d, dict):
        return None
    return d.get("content") or d.get("reasoning") or d.get("reasoning_content")


def _chat_once(spec, messages, model=None):
    """Non-streaming completion via the seat's own transports."""
    use = dict(spec)
    if model:
        use["id"] = model
    return seat.call_model(use, messages)


def _stream_deltas(spec, messages, model=None, stop=None):
    """Yield text deltas from the upstream. Falls back to one whole-text delta
    for providers without SSE (claude-cli) or on stream failure."""
    if spec.get("provider") == "claude-cli":
        use = dict(spec)
        if model:
            use["id"] = model
        yield seat.call_claude_cli(use, messages)
        return
    url = spec["base_url"].rstrip("/") + "/chat/completions"
    payload = json.dumps({
        "model": model or spec["id"],
        "messages": messages,
        "max_tokens": spec.get("max_tokens", 4096),
        "stream": True,
    }).encode()
    headers = {"Content-Type": "application/json"}
    if spec.get("api_key"):
        headers["Authorization"] = f"Bearer {spec['api_key']}"
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=CHAT_TIMEOUT) as resp:
            for raw in resp:
                if stop is not None and stop.is_set():
                    return
                line = raw.decode("utf-8", "replace").strip()
                if not line.startswith("data:"):
                    continue
                chunk = line[len("data:"):].strip()
                if chunk == "[DONE]":
                    return
                try:
                    obj = json.loads(chunk)
                    delta = _extract_delta(obj)
                except Exception:
                    delta = None
                if delta:
                    yield delta
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:300]
        yield f"[error] upstream HTTP {exc.code}: {body}"
    except Exception as exc:  # noqa: BLE001
        yield f"[error] {(str(exc) or exc.__class__.__name__)[:200]}"


# --------------------------------------------------------------------------
# Exec bridge implementation (local shell, guarded, default OFF)
# --------------------------------------------------------------------------
def _extract_exec_blocks(text):
    if not text:
        return []
    return [m.group(1).strip() for m in _EXEC_FENCE_RE.finditer(text)]


def _exec_blocked(cmd):
    for name, rx in _EXEC_BLOCKLIST:
        if rx.search(cmd or ""):
            return name
    return None


def _audit_exec(cid, source, cmd, blocked, exit_code, timed_out, dur_ms, error=None):
    try:
        rec = {
            "ts": round(time.time(), 3), "conversation_id": cid, "source": source,
            "cmd": (cmd or "")[:2000], "blocked": bool(blocked), "exit_code": exit_code,
            "timed_out": bool(timed_out), "duration_ms": int(dur_ms),
            "error": (str(error)[:300] if error else None),
        }
        with open(AUDIT_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _local_exec(cmd, timeout_s):
    """Run cmd in the local shell. Never raises."""
    t0 = time.time()
    result = {"exit_code": None, "stdout": "", "stderr": "", "timed_out": False, "error": None}
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout_s
        )
        result.update(exit_code=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
    except subprocess.TimeoutExpired as exc:
        result.update(
            timed_out=True,
            stdout=(exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            stderr=(exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
        )
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)[:200]
        result["stderr"] = f"[exec bridge error] {result['error']}"
    result["duration_ms"] = int((time.time() - t0) * 1000)
    return result


def _format_exec_output(res, cap=None):
    out = f"exit={res.get('exit_code')}\n{(res.get('stdout') or '')}"
    if res.get("stderr"):
        out += (("\n" + res["stderr"]) if out else res["stderr"])
    if res.get("timed_out"):
        out += "\n[timed out]"
    if res.get("error") and not (res.get("stderr") or "").startswith("[exec bridge error]"):
        out += f"\n[bridge] {res['error']}"
    limit = cap or EXEC_MAX_OUTPUT
    if len(out) > limit:
        out = out[:limit] + "\n...[truncated]"
    return out


def _ensure_exec_system(messages):
    msgs = list(messages or [])
    instr = "\n\n" + EXEC_SYSTEM_PROMPT
    if msgs and msgs[0].get("role") == "system":
        msgs[0] = dict(msgs[0])
        msgs[0]["content"] = (msgs[0].get("content") or "") + instr
    else:
        msgs = [{"role": "system", "content": EXEC_SYSTEM_PROMPT}] + msgs
    return msgs


def _run_exec_round(cid, source, cmds):
    results = []
    for cmd in cmds:
        blocked = _exec_blocked(cmd)
        t0 = time.time()
        if blocked:
            out = f"[blocked by guardrail: {blocked}]"
            _audit_exec(cid, source, cmd, True, None, False, (time.time() - t0) * 1000)
        else:
            res = _local_exec(cmd, EXEC_TIMEOUT_S)
            out = _format_exec_output(res)
            _audit_exec(cid, source, cmd, False, res.get("exit_code"), res.get("timed_out"),
                        res.get("duration_ms", 0), res.get("error"))
        results.append((cmd, out))
    return results


_EXEC_BLOCK_RE = re.compile(r"(\*\*\[exec\]\*\* `\$ [^\n]*`\n\n```\n)(.*?)(\n```)", re.S)
_EXEC_INPUT_RE = re.compile(r"(```exec\n)(.*?)(```)", re.S)


def _compact_history(messages):
    """Collapse old exec output in the COPY of the history sent upstream.
    The stored conversation and the browser transcript keep every byte."""
    total = sum(len(m.get("content") or "") for m in messages)
    if total <= HISTORY_BUDGET_CHARS:
        return (messages, 0, 0)

    hits = []
    for i, m in enumerate(messages):
        c = m.get("content")
        if not isinstance(c, str):
            continue
        if m.get("role") == "user" and c.startswith("EXEC RESULT:\n"):
            hits.append((i, 13, len(c), c[13:]))
            continue
        for mt in _EXEC_BLOCK_RE.finditer(c):
            hits.append((i, mt.start(2), mt.end(2), mt.group(2)))
        for mt in _EXEC_INPUT_RE.finditer(c):
            hits.append((i, mt.start(2), mt.end(2), mt.group(2)))
    hits.sort(key=lambda h: (h[0], h[1]))

    protected, running = set(), 0
    for i, s, _e, out in reversed(hits):
        if running >= HISTORY_EXEC_PROTECT_CHARS:
            break
        protected.add((i, s))
        running += len(out)

    edits, freed, collapsed = {}, 0, 0
    for i, s, e, out in hits:
        if (i, s) in protected:
            continue
        repl = out[:HISTORY_EXEC_HEAD_CHARS] + (
            f"\n[collapsed: {len(out)} chars of exec output — "
            f"full text kept in the Desk transcript]")
        if len(repl) >= len(out):
            continue
        edits.setdefault(i, []).append((s, e, repl))
        freed += len(out) - len(repl)
        collapsed += 1

    out_msgs = list(messages)
    for i, spans in edits.items():
        c = messages[i]["content"]
        for s, e, repl in sorted(spans, reverse=True):
            c = c[:s] + repl + c[e:]
        out_msgs[i] = {**messages[i], "content": c}

    # Backstop: still over budget -> truncate older turns to a head, newest first.
    if sum(len(m.get("content") or "") for m in out_msgs) > HISTORY_BUDGET_CHARS:
        running = 0
        for i in range(len(out_msgs) - 1, -1, -1):
            c = out_msgs[i].get("content") or ""
            if running + len(c) <= HISTORY_BUDGET_CHARS or i == len(out_msgs) - 1:
                running += len(c)
                continue
            if len(c) <= HISTORY_MSG_HEAD_CHARS + 80:
                running += len(c)
                continue
            head = c[:HISTORY_MSG_HEAD_CHARS]
            repl = head + (f"\n\n[older turn truncated: {len(c) - len(head)} further chars "
                           f"— full text kept in the Desk transcript]")
            freed += len(c) - len(repl)
            collapsed += 1
            out_msgs[i] = {**out_msgs[i], "content": repl}
            running += len(repl)

    if not collapsed:
        return (messages, 0, 0)
    return (out_msgs, collapsed, freed)


def _chat_stream_exec(spec, model, messages, cid, stop):
    """Multi-round streaming chat with the ```exec protocol. Yields SSE frames;
    pass-through single round when exec is disabled."""
    rounds = 0
    started = time.monotonic()
    messages, _n, _f = _compact_history(messages)
    if _n:
        yield _sse({"delta": f"\n_[context: collapsed {_n} older exec output(s), "
                             f"~{_f // 1000}k chars — full text stays in this transcript]_\n\n"})
    try:
        while True:
            collected = []
            for delta in _stream_deltas(spec, messages, model, stop):
                collected.append(delta)
                yield _sse({"delta": delta})
                if stop.is_set():
                    break
            if stop.is_set():
                break
            text = "".join(collected)
            if not text:
                text = _chat_once(spec, messages, model)
                if text:
                    yield _sse({"delta": text})
            rounds += 1
            cmds = _extract_exec_blocks(text) if EXEC_ENABLED else []
            if not cmds:
                break
            if rounds >= EXEC_MAX_ROUNDS:
                yield _sse({"delta":
                            f"\n\n_[exec budget spent after {EXEC_MAX_ROUNDS} rounds — "
                            f"{len(cmds)} command(s) not run. Ask again to continue.]_\n"})
                break
            spent = time.monotonic() - started
            if spent > EXEC_LOOP_BUDGET_S:
                yield _sse({"delta":
                            f"\n\n_[exec time budget spent: {spent:.0f}s of "
                            f"{EXEC_LOOP_BUDGET_S}s over {rounds} round(s) — "
                            f"{len(cmds)} command(s) not run. Ask again to continue.]_\n"})
                break
            results = _run_exec_round(cid, "chat", cmds)
            for cmd, out in results:
                yield _sse({"delta": f"\n\n**[exec]** `$ {cmd}`\n\n```\n{out}\n```\n"})
            messages = messages + [
                {"role": "assistant", "content": text},
                {"role": "user", "content": "EXEC RESULT:\n" + "\n\n".join(f"$ {c}\n{o}" for c, o in results)},
            ]
            messages, _n, _f = _compact_history(messages)
            if _n:
                yield _sse({"delta": f"\n_[context: collapsed {_n} older exec output(s), "
                                     f"~{_f // 1000}k chars]_\n"})
    except Exception as exc:  # noqa: BLE001
        yield _sse({"delta": f"[error] {(str(exc) or exc.__class__.__name__)[:200]}"})
    yield "data: [DONE]\n\n"


# --------------------------------------------------------------------------
# Detached generation registry. A reply keeps generating on the server even if
# the browser tab closes: the client streams by TAILING this buffer, so a
# disconnect stops the tail, never the generation. Re-attach via
# GET /api/chat/attach/{conversation_id}.
# --------------------------------------------------------------------------
_CONV_LOCK = threading.Lock()
_GENERATIONS = {}  # conversation_id -> {chunks, done, event, final, stop}


def _last_user_content(messages):
    for m in reversed(messages or []):
        if m.get("role") == "user":
            return m.get("content", "")
    return None


def _append_message(cid, role, content):
    if not cid:
        return
    with _CONV_LOCK:
        conv = _read_json(_conv_path(cid))
        if conv is None:
            return
        msgs = conv.get("messages", [])
        msgs.append({"role": role, "content": content})
        conv["messages"] = msgs
        conv["updated"] = time.time()
        _write_json(_conv_path(cid), conv)


def _run_generation(conv_id, spec, model, messages):
    g = _GENERATIONS[conv_id]
    collected = []
    try:
        for frame in _chat_stream_exec(spec, model, messages, conv_id, g["stop"]):
            if frame.startswith("data: {"):
                try:
                    d = json.loads(frame[len("data: "):].strip())
                    if d.get("delta") and not d.get("status"):
                        collected.append(d["delta"])
                except Exception:
                    pass
            g["chunks"].append(frame)
            g["event"].set()
        if g["stop"].is_set():
            collected.append("\n\n_[stopped]_")
            g["chunks"].append(_sse({"delta": "\n\n_[stopped]_"}))
    except Exception as exc:  # noqa: BLE001
        err = f"[error] {(str(exc) or exc.__class__.__name__)[:200]}"
        collected.append(err)
        g["chunks"].append(_sse({"delta": err}))
    finally:
        _append_message(conv_id, "assistant", "".join(collected) or "_[no output]_")
        g["final"] = "".join(collected)
        g["done"] = True
        if not g["chunks"] or not g["chunks"][-1].startswith("data: [DONE]"):
            g["chunks"].append("data: [DONE]\n\n")
        g["event"].set()


def _tail_generation(conv_id):
    """Replay buffered frames, then follow new ones until the reply is done."""
    g = _GENERATIONS.get(conv_id)
    if not g:
        yield "data: [DONE]\n\n"
        return
    i = 0
    while True:
        while i < len(g["chunks"]):
            yield g["chunks"][i]
            i += 1
        if g["done"]:
            return
        g["event"].clear()
        if not g["event"].wait(timeout=20):
            yield ": keepalive\n\n"


def _start_generation(conv_id, spec, model, messages):
    g = _GENERATIONS.get(conv_id)
    if g and not g["done"]:
        return
    _GENERATIONS[conv_id] = {
        "chunks": [], "done": False, "event": threading.Event(),
        "final": "", "stop": threading.Event(),
    }
    t = threading.Thread(
        target=_run_generation, args=(conv_id, spec, model, messages), daemon=True
    )
    t.start()


def _is_generating(conv_id):
    g = _GENERATIONS.get(conv_id)
    return bool(g and not g["done"])


# --------------------------------------------------------------------------
# Workflows
# --------------------------------------------------------------------------
def _load_workflows():
    out = []
    for fn in os.listdir(WF_DIR):
        if not fn.endswith(".json"):
            continue
        wf = _read_json(os.path.join(WF_DIR, fn))
        if wf:
            out.append(wf)
    out.sort(key=lambda w: w.get("name", ""))
    return out


def _render(template, original_input, prev):
    return (template or "").replace("{{input}}", original_input or "").replace(
        "{{prev}}", prev or ""
    )


def _default_provider():
    cfg = _cfg()
    keys = models.list_models(cfg)
    return keys[0] if keys else None


def _run_step(step, original_input, prev):
    provider_id = step.get("provider") or _default_provider()
    try:
        spec = _resolve(provider_id)
    except ApiError as exc:
        return f"[error] {exc.detail}"
    prompt = _render(step.get("prompt", ""), original_input, prev)
    messages = _build_messages([{"role": "user", "content": prompt}], step.get("system"))
    return _chat_once(spec, messages, step.get("model"))


# --------------------------------------------------------------------------
# Upload (stdlib multipart parse; text files attach as text)
# --------------------------------------------------------------------------
def _parse_multipart(body, ctype):
    """Return (filename, payload_bytes) of the first file part, or None."""
    m = re.search(r'boundary="?([^";]+)"?', ctype or "")
    if not m:
        return None
    boundary = b"--" + m.group(1).encode()
    for part in body.split(boundary):
        if not part or part in (b"--", b"--\r\n"):
            continue
        if part.startswith(b"\r\n"):
            part = part[2:]
        head, sep, payload = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        headers = head.decode("utf-8", "replace")
        fm = re.search(r'filename="([^"]*)"', headers)
        if not fm:
            continue
        if payload.endswith(b"\r\n"):
            payload = payload[:-2]
        return (fm.group(1), payload)
    return None


_TEXTY_EXT = {".txt", ".md", ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".csv",
              ".html", ".css", ".xml", ".sh", ".ps1", ".toml", ".ini", ".log", ".rs",
              ".go", ".c", ".h", ".cpp", ".java", ".rb", ".php", ".sql"}


def _ingest(stored_path, original, data, mime):
    ext = os.path.splitext(original)[1].lower()
    if (mime or "").startswith("text/") or ext in _TEXTY_EXT or not data[:8192].count(b"\x00"):
        try:
            return {"kind": "text", "text": data.decode("utf-8")}
        except UnicodeDecodeError:
            pass
    return {
        "kind": "binary",
        "text": (f"[attached file: {original} ({len(data)} bytes, {mime or 'unknown type'}) — "
                 f"stored at {stored_path}. The stdlib Desk does not extract text from "
                 f"binary files (no OCR/audio/PDF); paste the content as text if needed.]"),
        "note": "binary file stored; text not extracted (stdlib desk has no OCR/audio/PDF ingestion)",
    }


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------
_ASSET_REF = re.compile(r'(href|src)="(/static/[^"?]+)"')


def _asset_version(url):
    try:
        return str(int(os.path.getmtime(os.path.join(STATIC_DIR, url[len("/static/"):]))))
    except OSError:
        return "0"


_MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
         ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml",
         ".png": "image/png", ".ico": "image/x-icon"}


class DeskHandler(BaseHTTPRequestHandler):
    server_version = "SygnifDesk/1.0"

    # -- plumbing ----------------------------------------------------------
    def log_message(self, fmt, *args):  # quieter default log
        sys.stderr.write("desk: %s - %s\n" % (self.address_string(), fmt % args))

    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, detail):
        self._json({"detail": detail}, status=status)

    def _sse_response(self, frames):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            for frame in frames:
                self.wfile.write(frame.encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass  # client went away; a detached generation lives on

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_UPLOAD + 65536:
            raise ApiError(413, "request too large")
        return self.rfile.read(length) if length else b""

    def _body_json(self):
        raw = self._body()
        try:
            return json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            raise ApiError(400, "invalid JSON body")

    # -- routing -----------------------------------------------------------
    def do_GET(self):  # noqa: N802
        try:
            self._route("GET")
        except ApiError as exc:
            self._error(exc.status, exc.detail)

    def do_POST(self):  # noqa: N802
        try:
            self._route("POST")
        except ApiError as exc:
            self._error(exc.status, exc.detail)

    def do_PATCH(self):  # noqa: N802
        try:
            self._route("PATCH")
        except ApiError as exc:
            self._error(exc.status, exc.detail)

    def do_DELETE(self):  # noqa: N802
        try:
            self._route("DELETE")
        except ApiError as exc:
            self._error(exc.status, exc.detail)

    def _route(self, method):
        path = self.path.split("?", 1)[0]

        # ---- static SPA ----
        if method == "GET" and path == "/":
            return self._index()
        if method == "GET" and path.startswith("/static/"):
            return self._static(path[len("/static/"):])

        # ---- api ----
        if path == "/api/health" and method == "GET":
            return self._json({"status": "ok", "time": time.time()})
        if path == "/api/providers" and method == "GET":
            return self._json(api_providers())

        if path == "/api/chat" and method == "POST":
            return self._chat()
        m = re.fullmatch(r"/api/chat/stop/([\w-]+)", path)
        if m and method == "POST":
            return self._chat_stop(m.group(1))
        m = re.fullmatch(r"/api/chat/attach/([\w-]+)", path)
        if m and method == "GET":
            return self._sse_response(_tail_generation(m.group(1)))

        if path == "/api/conversations":
            if method == "GET":
                return self._json(self._list_conversations())
            if method == "POST":
                return self._create_conversation()
        m = re.fullmatch(r"/api/conversations/([\w-]+)", path)
        if m:
            cid = m.group(1)
            if method == "GET":
                conv = _read_json(_conv_path(cid))
                if conv is None:
                    raise ApiError(404, "conversation not found")
                conv["generating"] = _is_generating(cid)
                return self._json(conv)
            if method == "PATCH":
                return self._patch_conversation(cid)
            if method == "DELETE":
                p = _conv_path(cid)
                if os.path.exists(p):
                    os.remove(p)
                return self._json({"ok": True})

        if path == "/api/workflows":
            if method == "GET":
                return self._json(_load_workflows())
            if method == "POST":
                return self._save_workflow()
        m = re.fullmatch(r"/api/workflows/([\w-]+)/run", path)
        if m and method == "POST":
            return self._run_workflow(m.group(1))
        m = re.fullmatch(r"/api/workflows/([\w-]+)", path)
        if m:
            wid = m.group(1)
            if method == "GET":
                wf = _read_json(_wf_path(wid))
                if wf is None:
                    raise ApiError(404, "workflow not found")
                return self._json(wf)
            if method == "DELETE":
                p = _wf_path(wid)
                if os.path.exists(p):
                    os.remove(p)
                return self._json({"ok": True})

        if path == "/api/upload" and method == "POST":
            return self._upload()

        raise ApiError(404, f"no route: {method} {path}")

    # -- static ------------------------------------------------------------
    def _index(self):
        index_path = os.path.join(STATIC_DIR, "index.html")
        if not os.path.exists(index_path):
            body = b"SYGNIF Desk backend is running. static/index.html not found."
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        with open(index_path, encoding="utf-8") as fh:
            html = fh.read()
        html = _ASSET_REF.sub(
            lambda m: f'{m.group(1)}="{m.group(2)}?v={_asset_version(m.group(2))}"', html)
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, must-revalidate")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _static(self, rel):
        full = os.path.realpath(os.path.join(STATIC_DIR, rel))
        if not full.startswith(os.path.realpath(STATIC_DIR) + os.sep) or not os.path.isfile(full):
            raise ApiError(404, "not found")
        ext = os.path.splitext(full)[1].lower()
        with open(full, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", _MIME.get(ext, "application/octet-stream"))
        self.send_header("Cache-Control", "no-cache, must-revalidate")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -- chat ---------------------------------------------------------------
    def _chat(self):
        body = self._body_json()
        spec = _resolve(body.get("provider"))
        model = body.get("model") or spec.get("id")
        raw_messages = body.get("messages", [])
        system = body.get("system")
        conversation_id = body.get("conversation_id")
        stream = bool(body.get("stream", False))

        messages = _build_messages(raw_messages, system)
        if EXEC_ENABLED:
            messages = _ensure_exec_system(messages)

        # Persist the user turn BEFORE any upstream work — a tab close or a dead
        # provider must never lose what the user typed.
        user_text = _last_user_content(raw_messages)
        if user_text is not None:
            _append_message(conversation_id, "user", user_text)

        if stream:
            _start_generation(conversation_id, spec, model, messages)
            return self._sse_response(_tail_generation(conversation_id))

        # Non-streaming: run the exec loop to completion in-request.
        stopper = threading.Event()
        collected = []
        for frame in _chat_stream_exec(spec, model, messages, conversation_id, stopper):
            if frame.startswith("data: {"):
                try:
                    d = json.loads(frame[len("data: "):].strip())
                    if d.get("delta"):
                        collected.append(d["delta"])
                except Exception:
                    pass
        content = "".join(collected)
        _append_message(conversation_id, "assistant", content or "_[no output]_")
        return self._json({"content": content, "provider": body.get("provider"), "model": model})

    def _chat_stop(self, cid):
        g = _GENERATIONS.get(cid)
        if not g or g["done"]:
            return self._json({"stopped": False, "reason": "not generating"})
        g["stop"].set()
        g["event"].set()
        return self._json({"stopped": True})

    # -- conversations -------------------------------------------------------
    def _list_conversations(self):
        items = []
        for fn in os.listdir(CONV_DIR):
            if not fn.endswith(".json"):
                continue
            conv = _read_json(os.path.join(CONV_DIR, fn))
            if not conv:
                continue
            msgs = conv.get("messages") or []
            last = msgs[-1] if msgs else {}
            tail = last.get("content", "") if last.get("role") == "assistant" else ""
            items.append({
                "id": conv.get("id"),
                "title": conv.get("title", "Untitled"),
                "updated": conv.get("updated", 0),
                "generating": _is_generating(conv.get("id")),
                "interrupted": tail.rstrip().endswith(("_[stopped]_", "_[interrupted]_")),
            })
        items.sort(key=lambda x: x.get("updated") or 0, reverse=True)
        return items

    def _create_conversation(self):
        body = self._body_json()
        cid = uuid.uuid4().hex[:12]
        conv = {
            "id": cid,
            "title": body.get("title") or "New conversation",
            "system": body.get("system") or "",
            "messages": [],
            "updated": time.time(),
        }
        _write_json(_conv_path(cid), conv)
        return self._json(conv)

    def _patch_conversation(self, cid):
        conv = _read_json(_conv_path(cid))
        if conv is None:
            raise ApiError(404, "conversation not found")
        body = self._body_json()
        for field in ("title", "system", "messages"):
            if field in body:
                conv[field] = body[field]
        conv["updated"] = time.time()
        _write_json(_conv_path(cid), conv)
        return self._json(conv)

    # -- workflows -------------------------------------------------------------
    def _save_workflow(self):
        body = self._body_json()
        wid = body.get("id") or ("wf-" + uuid.uuid4().hex[:8])
        wf = {
            "id": wid,
            "name": body.get("name") or "Untitled workflow",
            "steps": body.get("steps") or [],
        }
        _write_json(_wf_path(wid), wf)
        return self._json(wf)

    def _run_workflow(self, wid):
        wf = _read_json(_wf_path(wid))
        if wf is None:
            raise ApiError(404, "workflow not found")
        body = self._body_json()
        original_input = body.get("input", "")
        stream = bool(body.get("stream", False))
        steps = wf.get("steps", [])

        if stream:
            def gen():
                prev = ""
                for i, step in enumerate(steps):
                    name = step.get("name", f"step {i}")
                    output = _run_step(step, original_input, prev)
                    yield _sse({"step": i, "name": name, "delta": output})
                    yield _sse({"step": i, "name": name, "done": True})
                    prev = output
                yield "data: [DONE]\n\n"
            return self._sse_response(gen())

        results = []
        prev = ""
        for i, step in enumerate(steps):
            output = _run_step(step, original_input, prev)
            results.append({"name": step.get("name", f"step {i}"), "output": output})
            prev = output
        return self._json({"steps": results, "final": prev})

    # -- upload ------------------------------------------------------------
    def _upload(self):
        ctype = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in ctype:
            raise ApiError(400, "expected multipart/form-data")
        body = self._body()
        parsed = _parse_multipart(body, ctype)
        if not parsed:
            raise ApiError(400, "no file part found")
        original, data = parsed
        if len(data) > MAX_UPLOAD:
            raise ApiError(413, "file exceeds 25MB limit")
        if not data:
            raise ApiError(422, "uploaded file is empty (0 bytes) — re-attach it")

        fid = uuid.uuid4().hex[:12]
        original = original or "upload.bin"
        safe = original.replace("/", "_").replace("\\", "_")
        stored_path = os.path.join(UPLOAD_DIR, f"{fid}_{safe}")
        with open(stored_path, "wb") as fh:
            fh.write(data)

        info = _ingest(stored_path, original, data, "")
        resp = {
            "id": fid, "filename": original, "size": len(data), "mime": "",
            "kind": info["kind"], "text": info["text"], "stored_path": stored_path,
        }
        if info.get("note"):
            resp["note"] = info["note"]
        return self._json(resp)


def main():
    _seed_workflows()
    cfg = _cfg()
    keys = models.list_models(cfg)
    exec_note = "ON (local shell)" if EXEC_ENABLED else "off (SYGNIF_DESK_EXEC=1 to enable)"
    print(f"SYGNIF Desk — http://{HOST}:{PORT}  providers={keys}  "
          f"data={DATA_DIR}  exec={exec_note}")
    srv = ThreadingHTTPServer((HOST, PORT), DeskHandler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nSYGNIF Desk — stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
