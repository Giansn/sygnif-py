"""Tool layer for SYGNIF py (the generic seat).

Built-in tools, all operating on the local machine as the seat user:
  * shell        — run a command on this host and return stdout+stderr+exit code.
  * read_file    — read a UTF-8 text file (optionally a line range).
  * write_file   — write/overwrite a UTF-8 text file (creates parent dirs).
  * note         — append a line to the working journal.
  * dev_apply_and_test — write one or more files, then run a check/test command
                   and report the combined result (the build->prove loop in one
                   call). This is SYGNIF py's generic "development" hand.
  * centre       — dispatch a neuron on a running SYGNIF py Centre (the knot
                   point: sys.state, note.*, knowledge.*, plus your own neurons).
  * commander    — call a tool on a running SYGNIF py commander (the hands:
                   sandboxed fs ops, code search, named-command exec).

Extensibility: drop a `custom_tools.py` next to this file, or a
`~/.sygnif/sygnif-py-tools.py`, that defines `register(reg)` and mutates the
registry dict. See custom_tools.py.example.
"""
from __future__ import annotations

import datetime
import json
import os
import subprocess
import urllib.error
import urllib.request

SEAT_DIR = os.path.dirname(os.path.abspath(__file__))

SHELL_TIMEOUT = int(os.environ.get("SYGNIF_PY_SHELL_TIMEOUT", "120"))
MAX_OUTPUT = int(os.environ.get("SYGNIF_PY_MAXOUT", "8000"))
MAX_READ = int(os.environ.get("SYGNIF_PY_MAXREAD", "20000"))
JOURNAL = os.path.expanduser(
    os.environ.get("SYGNIF_PY_JOURNAL", "~/.sygnif/sygnif-py-journal.md")
)
DEV_TEST_TIMEOUT = int(os.environ.get("SYGNIF_PY_DEV_TEST_TIMEOUT", "300"))
CENTRE_URL = os.environ.get("SYGNIF_PY_CENTRE_URL", "http://127.0.0.1:9100")
CENTRE_TOKEN = os.environ.get("SYGNIF_PY_CENTRE_TOKEN", "").strip()
COMMANDER_URL = os.environ.get("SYGNIF_PY_COMMANDER_URL", "http://127.0.0.1:9110")
COMMANDER_TOKEN = os.environ.get("SYGNIF_PY_COMMANDER_TOKEN", "").strip()
HTTP_TIMEOUT = int(os.environ.get("SYGNIF_PY_TOOL_HTTP_TIMEOUT", "600"))

# On Windows there is no bash; fall back to the platform default shell.
_IS_WINDOWS = os.name == "nt"


def _truncate(text: str, limit: int = MAX_OUTPUT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[... output truncated at {limit} chars ...]"


def _run_host(command: str, timeout: int) -> tuple[str, int]:
    """Run a command string on the host. Never raises."""
    try:
        if _IS_WINDOWS:
            args, shell = command, True
        else:
            args, shell = ["bash", "-lc", command], False
        p = subprocess.run(
            args, shell=shell, capture_output=True, text=True, timeout=timeout
        )
        return (p.stdout or "") + (p.stderr or ""), p.returncode
    except subprocess.TimeoutExpired:
        return f"[timeout after {timeout}s]", 124
    except Exception as e:  # noqa: BLE001 - surface to the model, never crash the seat
        return f"[host exec error: {e}]", 1


# --- built-in tools ---------------------------------------------------------


def tool_shell(args: dict) -> str:
    command = str(args.get("command", "")).strip()
    if not command:
        return "shell: empty command"
    out, rc = _run_host(command, SHELL_TIMEOUT)
    return _truncate(out) + f"\nexit={rc}"


def tool_read_file(args: dict) -> str:
    path = os.path.expanduser(str(args.get("path", "")).strip())
    if not path:
        return "read_file: empty path"
    start = int(args.get("start", 0) or 0)
    end = args.get("end")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except Exception as e:  # noqa: BLE001
        return f"[read_file error: {e}]"
    if start or end is not None:
        lines = lines[start : (int(end) if end is not None else None)]
    return _truncate("".join(lines), MAX_READ) or "(empty)"


def tool_write_file(args: dict) -> str:
    path = os.path.expanduser(str(args.get("path", "")).strip())
    content = args.get("content", "")
    if not path:
        return "write_file: empty path"
    if not isinstance(content, str):
        content = str(content)
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    except Exception as e:  # noqa: BLE001
        return f"[write_file error: {e}]"
    return f"wrote {len(content)} chars -> {path}"


def tool_note(args: dict) -> str:
    text = str(args.get("text", "")).strip()
    if not text:
        return "note: empty text"
    try:
        os.makedirs(os.path.dirname(JOURNAL), exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(JOURNAL, "a", encoding="utf-8") as fh:
            fh.write(f"- [{ts}] {text}\n")
    except Exception as e:  # noqa: BLE001
        return f"[note error: {e}]"
    return f"noted -> {JOURNAL}"


def tool_dev_apply_and_test(args: dict) -> str:
    """Write file(s), then run a check/test command, and report both outcomes.

    This is the generic 'development' hand: it turns an edit + a proof into one
    step, so the model can't claim done without the check actually running.

    Args:
      path + content       — write one file, OR
      files: [{path, content}, ...] — write several, then
      test                 — a shell command to prove it (pytest, build, run…).
    """
    written: list[str] = []
    batch = args.get("files")
    if not isinstance(batch, list):
        batch = []
        if args.get("path"):
            batch = [{"path": args.get("path"), "content": args.get("content", "")}]
    for spec in batch:
        if not isinstance(spec, dict) or not spec.get("path"):
            continue
        r = tool_write_file({"path": spec["path"], "content": spec.get("content", "")})
        written.append(r)
    test = str(args.get("test", "")).strip()
    parts = ["writes:"]
    parts.extend(f"  - {w}" for w in written) if written else parts.append("  (no files written)")
    if not test:
        parts.append("test: (none given — pass a 'test' command to prove the change)")
        return "\n".join(parts)
    out, rc = _run_host(test, DEV_TEST_TIMEOUT)
    parts.append(f"test: {test}")
    parts.append(_truncate(out))
    parts.append(f"exit={rc}  ({'PASS' if rc == 0 else 'FAIL'})")
    return "\n".join(parts)


def _http_json(url: str, payload: dict, token: str) -> tuple[dict | None, str]:
    """POST JSON, return (parsed, error). Never raises."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode()), ""
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}: {e.read().decode(errors='replace')[:300]}"
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"


def tool_centre(args: dict) -> str:
    """Dispatch a neuron on the running Centre (SYGNIF_PY_CENTRE_URL)."""
    neuron = str(args.get("neuron", "")).strip()
    if not neuron:
        return "centre: give a 'neuron' (e.g. sys.state, knowledge.search, note.write)"
    payload = {"tool": neuron, "args": args.get("args") or {}}
    data, err = _http_json(CENTRE_URL.rstrip("/") + "/rpc", payload, CENTRE_TOKEN)
    if err:
        return f"[centre unreachable at {CENTRE_URL}: {err} — is `sygnif-centre` running?]"
    return _truncate(json.dumps(data, indent=2, default=str))


def tool_commander(args: dict) -> str:
    """Call a tool on the running commander (SYGNIF_PY_COMMANDER_URL)."""
    name = str(args.get("name", "")).strip()
    if not name:
        return "commander: give a tool 'name' (e.g. fs_read, code_search, proc_exec)"
    if not COMMANDER_TOKEN:
        return ("commander: SYGNIF_PY_COMMANDER_TOKEN is not set in this seat's "
                "environment — start the commander and export its token so the seat can auth.")
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": name, "arguments": args.get("args") or {}}}
    data, err = _http_json(COMMANDER_URL.rstrip("/") + "/rpc", payload, COMMANDER_TOKEN)
    if err:
        return f"[commander unreachable at {COMMANDER_URL}: {err} — is `sygnif-commander` running?]"
    if isinstance(data, dict) and data.get("error"):
        return f"[commander error: {json.dumps(data['error'])}]"
    try:
        return _truncate(data["result"]["content"][0]["text"])
    except Exception:
        return _truncate(json.dumps(data, indent=2, default=str))


# name -> {desc, args (name->hint), func}
BUILTIN_TOOLS: dict[str, dict] = {
    "shell": {
        "desc": (
            "Run a command on THIS machine (as the seat user) and return its "
            "stdout, stderr and exit code. Use it to inspect the system, run "
            "builds/tests, or drive any CLI tool that is installed."
        ),
        "args": {"command": "the shell command to run, e.g. 'ls -la ~'"},
        "func": tool_shell,
    },
    "read_file": {
        "desc": "Read a UTF-8 text file. Optional 0-based 'start'/'end' line range.",
        "args": {
            "path": "file path (supports ~)",
            "start": "optional first line (0-based)",
            "end": "optional end line (exclusive)",
        },
        "func": tool_read_file,
    },
    "write_file": {
        "desc": "Write (overwrite) a UTF-8 text file, creating parent dirs as needed.",
        "args": {"path": "file path (supports ~)", "content": "full file contents"},
        "func": tool_write_file,
    },
    "note": {
        "desc": "Append a timestamped line to the working journal — record decisions, findings, and where evidence lives.",
        "args": {"text": "the note to record"},
        "func": tool_note,
    },
    "dev_apply_and_test": {
        "desc": (
            "Development hand: write one or more files, then run a check/test "
            "command and report BOTH the writes and the test result (stdout + "
            "PASS/FAIL). Use this to make a change and prove it in one step — "
            "never claim a build works without the test actually passing here."
        ),
        "args": {
            "path": "single file to write (use with 'content')",
            "content": "contents for 'path'",
            "files": "OR a list of {path, content} objects to write together",
            "test": "shell command that proves the change (e.g. 'pytest -q', 'python x.py', 'npm test')",
        },
        "func": tool_dev_apply_and_test,
    },
    "centre": {
        "desc": (
            "Ask the SYGNIF py Centre (the knot point) for a capability. Dispatch "
            "a neuron by name: 'sys.state' (host snapshot), 'sys.procs', "
            "'knowledge.search'/'knowledge.read', 'note.write'/'note.read', plus "
            "any neurons the operator has added. Requires `sygnif-centre` running."
        ),
        "args": {
            "neuron": "neuron name, e.g. 'sys.state' or 'knowledge.search'",
            "args": "object of arguments for that neuron (may be empty)",
        },
        "func": tool_centre,
    },
    "commander": {
        "desc": (
            "Use the SYGNIF py commander (the hands) for sandboxed, allowlisted "
            "operations on a host: 'fs_read'/'fs_write'/'fs_list', 'code_search', "
            "'proc_exec' (named commands only). Requires `sygnif-commander` "
            "running and its token exported to this seat."
        ),
        "args": {
            "name": "commander tool, e.g. 'fs_read', 'code_search', 'proc_exec'",
            "args": "object of arguments for that tool",
        },
        "func": tool_commander,
    },
}


def _load_plugins(reg: dict) -> None:
    """Let the operator extend the registry from a drop-in file."""
    for path in (
        os.path.join(SEAT_DIR, "custom_tools.py"),
        os.path.expanduser("~/.sygnif/sygnif-py-tools.py"),
    ):
        if not os.path.isfile(path):
            continue
        ns: dict = {}
        try:
            with open(path, encoding="utf-8") as fh:
                exec(compile(fh.read(), path, "exec"), ns)  # noqa: S102 - operator's own file
            if callable(ns.get("register")):
                ns["register"](reg)
        except Exception as e:  # noqa: BLE001
            print(f"[sygnif-py] plugin {path} failed to load: {e}")


def build_registry(tool_names: list[str]) -> dict:
    """Return the active tool registry for a preset's tool list, plus plugins."""
    reg = {n: dict(BUILTIN_TOOLS[n]) for n in tool_names if n in BUILTIN_TOOLS}
    _load_plugins(reg)
    return reg


def run_tool(reg: dict, name: str, args: dict) -> str:
    tool = reg.get(name)
    if not tool:
        return f"[unknown tool '{name}'. available: {', '.join(reg) or '(none)'}]"
    try:
        return tool["func"](args or {})
    except Exception as e:  # noqa: BLE001
        return f"[tool '{name}' raised: {e}]"
