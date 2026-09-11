#!/usr/bin/env python3
"""SYGNIF py — commander (the hands).

A small, dependency-free HTTP server that exposes the machine's hands to a
SYGNIF seat: read/write/list files, search code, run named commands, and drive
long-running processes as sessions. It is the generic, self-contained sibling of
the SYGNIF stack's "commander" control plane — the thing a seat talks to when it
needs to *do* something on a host rather than just think.

Posture: default-deny. Two gates, both configurable:
  * PATHS   — every path argument is realpath'd and must sit under an allowed
              root. Nothing outside the allowlist is readable or writable.
  * COMMANDS— exec only runs NAMED commands from an allowlist (a JSON map of
              name -> argv). There is no raw shell here; the seat's own `shell`
              tool is for that. Until the operator defines commands, exec is off.

Transport: HTTP POST /rpc with a JSON-RPC 2.0 body (MCP-flavoured:
initialize / tools/list / tools/call). GET /health for a liveness probe.
Auth: bearer token from SYGNIF_PY_COMMANDER_TOKEN. The server FAILS CLOSED —
if no token is set it refuses to start, so a misconfig can never run it open.

Run:
    SYGNIF_PY_COMMANDER_TOKEN=$(openssl rand -hex 32) \\
    python3 commander.py
    # or use the sygnif-commander launcher, which mints a token for you.

Env knobs (all optional except the token):
    SYGNIF_PY_COMMANDER_TOKEN        bearer token (REQUIRED; no default)
    SYGNIF_PY_COMMANDER_BIND         bind host (default 127.0.0.1)
    SYGNIF_PY_COMMANDER_PORT         bind port (default 9110)
    SYGNIF_PY_COMMANDER_PATHS        colon-separated allowed roots
    SYGNIF_PY_COMMANDER_COMMANDS     JSON {name: ["argv0","argv1", ...]}
    SYGNIF_PY_COMMANDER_EXEC_TIMEOUT default per-exec timeout seconds (30)
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "sygnif-py-commander"
SERVER_VERSION = "1.0.0"
BIND_HOST = os.environ.get("SYGNIF_PY_COMMANDER_BIND", "127.0.0.1")
BIND_PORT = int(os.environ.get("SYGNIF_PY_COMMANDER_PORT", "9110"))
TOKEN = os.environ.get("SYGNIF_PY_COMMANDER_TOKEN", "").strip()

HOME = Path.home()

# --- allowlists — default-deny --------------------------------------------

# Generic default roots: a scratch/work dir, the SYGNIF state dir, and a tmp
# area. Override with SYGNIF_PY_COMMANDER_PATHS (colon-separated absolute paths).
_DEFAULT_PATHS = [
    str(HOME / "sygnif-py-work"),
    str(HOME / ".sygnif"),
    str(HOME / ".sygnif-py"),
    "/tmp/sygnif-py",
]
ALLOWED_PATHS = [
    str(Path(p).expanduser().resolve())
    for p in os.environ.get(
        "SYGNIF_PY_COMMANDER_PATHS", ":".join(_DEFAULT_PATHS)
    ).split(":")
    if p
]


def log(msg: str) -> None:
    sys.stderr.write(f"[{SERVER_NAME}] {msg}\n")
    sys.stderr.flush()


def _load_named_commands() -> dict[str, list[str]]:
    raw = os.environ.get("SYGNIF_PY_COMMANDER_COMMANDS", "").strip()
    if not raw:
        return {}
    try:
        obj = json.loads(raw)
    except Exception as e:  # noqa: BLE001
        log(f"SYGNIF_PY_COMMANDER_COMMANDS is not valid JSON: {e}")
        return {}
    out: dict[str, list[str]] = {}
    for name, argv in obj.items():
        if not isinstance(argv, list) or not all(isinstance(x, str) for x in argv):
            log(f"command {name!r} skipped: argv must be list[str]")
            continue
        if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{0,63}", name):
            log(f"command {name!r} skipped: bad name")
            continue
        out[name] = argv
    return out


NAMED_COMMANDS: dict[str, list[str]] = _load_named_commands()

EXEC_TIMEOUT_DEFAULT = int(os.environ.get("SYGNIF_PY_COMMANDER_EXEC_TIMEOUT", "30"))
EXEC_TIMEOUT_MAX = int(os.environ.get("SYGNIF_PY_COMMANDER_EXEC_TIMEOUT_MAX", "300"))
WRITE_MAX_BYTES = int(os.environ.get("SYGNIF_PY_COMMANDER_WRITE_MAX", str(2 * 1024 * 1024)))
READ_MAX_BYTES = int(os.environ.get("SYGNIF_PY_COMMANDER_READ_MAX", str(4 * 1024 * 1024)))


# --- path gate --------------------------------------------------------------


class DeniedPath(PermissionError):
    pass


def _resolve(p: str, *, must_exist: bool = False) -> Path:
    if not isinstance(p, str) or not p:
        raise ValueError("path must be a non-empty string")
    rp = Path(p).expanduser()
    try:
        rp = rp.resolve(strict=must_exist)
    except FileNotFoundError:
        rp = rp.resolve()
    s = str(rp)
    for root in ALLOWED_PATHS:
        if s == root or s.startswith(root + os.sep):
            return rp
    raise DeniedPath(f"path outside allowlist: {s}")


# --- session registry for long-running processes ----------------------------


class Session:
    __slots__ = ("id", "name", "argv", "proc", "started", "lock", "stdout_buf", "stderr_buf", "_readers")

    def __init__(self, sid: str, name: str, argv: list[str], proc: subprocess.Popen) -> None:
        self.id = sid
        self.name = name
        self.argv = argv
        self.proc = proc
        self.started = time.time()
        self.lock = threading.Lock()
        self.stdout_buf: list[str] = []
        self.stderr_buf: list[str] = []
        self._readers: list[threading.Thread] = []
        for stream, buf in ((proc.stdout, self.stdout_buf), (proc.stderr, self.stderr_buf)):
            if stream is None:
                continue
            t = threading.Thread(target=self._pump, args=(stream, buf), daemon=True)
            t.start()
            self._readers.append(t)

    def _pump(self, stream, buf: list[str]) -> None:
        try:
            for line in iter(stream.readline, ""):
                with self.lock:
                    buf.append(line)
                    if sum(len(x) for x in buf) > 1024 * 1024:
                        while buf and sum(len(x) for x in buf) > 768 * 1024:
                            buf.pop(0)
        except Exception:
            pass

    def drain(self) -> tuple[str, str]:
        with self.lock:
            out = "".join(self.stdout_buf); self.stdout_buf.clear()
            err = "".join(self.stderr_buf); self.stderr_buf.clear()
        return out, err

    def info(self) -> dict:
        return {
            "session_id": self.id,
            "name": self.name,
            "argv": self.argv,
            "pid": self.proc.pid,
            "running": self.proc.poll() is None,
            "exit_code": self.proc.returncode,
            "uptime_s": round(time.time() - self.started, 2),
        }


SESSIONS: dict[str, Session] = {}
SESSIONS_LOCK = threading.Lock()


def _reap_dead_sessions() -> None:
    with SESSIONS_LOCK:
        for sid in list(SESSIONS.keys()):
            s = SESSIONS[sid]
            if s.proc.poll() is not None and (time.time() - s.started) > 300:
                del SESSIONS[sid]


# --- tool implementations ---------------------------------------------------


def _stat_dict(p: Path) -> dict:
    st = p.stat()
    return {
        "path": str(p),
        "type": "dir" if p.is_dir() else ("symlink" if p.is_symlink() else "file"),
        "size": st.st_size,
        "mtime": st.st_mtime,
        "mode": stat.filemode(st.st_mode),
        "uid": st.st_uid,
        "gid": st.st_gid,
    }


def t_fs_read(args: dict) -> dict:
    path = _resolve(args["path"], must_exist=True)
    if not path.is_file():
        raise IsADirectoryError(f"not a file: {path}")
    if path.stat().st_size > READ_MAX_BYTES:
        raise ValueError(f"file exceeds READ_MAX_BYTES={READ_MAX_BYTES}")
    offset = int(args.get("offset", 0))
    limit = args.get("limit")
    encoding = args.get("encoding", "utf-8")
    try:
        with path.open("r", encoding=encoding, errors="replace") as f:
            lines = f.readlines()
    except UnicodeDecodeError as e:
        raise ValueError(f"binary file (use a different tool): {e}")
    total = len(lines)
    end = total if limit is None else min(total, offset + int(limit))
    chunk = lines[offset:end]
    return {
        "path": str(path),
        "lines_total": total,
        "lines_returned": len(chunk),
        "offset": offset,
        "content": "".join(chunk),
    }


def t_fs_write(args: dict) -> dict:
    path = _resolve(args["path"])
    content = args.get("content", "")
    if not isinstance(content, str):
        raise ValueError("content must be a string")
    if len(content.encode("utf-8")) > WRITE_MAX_BYTES:
        raise ValueError(f"content exceeds WRITE_MAX_BYTES={WRITE_MAX_BYTES}")
    mode = args.get("mode", "rewrite")
    if mode not in ("rewrite", "append"):
        raise ValueError("mode must be 'rewrite' or 'append'")
    path.parent.mkdir(parents=True, exist_ok=True)
    flag = "w" if mode == "rewrite" else "a"
    with path.open(flag, encoding="utf-8") as f:
        f.write(content)
    return {"path": str(path), "mode": mode, "bytes": len(content.encode("utf-8"))}


def t_fs_list(args: dict) -> dict:
    path = _resolve(args["path"], must_exist=True)
    if not path.is_dir():
        raise NotADirectoryError(f"not a directory: {path}")
    depth = max(0, min(int(args.get("depth", 2)), 6))
    entries: list[dict] = []
    base_depth = len(path.parts)
    for root, dirs, files in os.walk(path):
        cur_depth = len(Path(root).parts) - base_depth
        if cur_depth > depth:
            dirs[:] = []
            continue
        for d in sorted(dirs):
            entries.append({"path": str(Path(root) / d), "type": "dir"})
        for f in sorted(files):
            try:
                entries.append(_stat_dict(Path(root) / f))
            except OSError:
                continue
        if len(entries) >= 2000:
            entries.append({"_truncated": True})
            break
    return {"path": str(path), "depth": depth, "count": len(entries), "entries": entries}


def t_fs_info(args: dict) -> dict:
    return _stat_dict(_resolve(args["path"], must_exist=True))


def t_fs_mkdir(args: dict) -> dict:
    path = _resolve(args["path"])
    path.mkdir(parents=True, exist_ok=True)
    return {"path": str(path), "created": True}


def t_fs_move(args: dict) -> dict:
    src = _resolve(args["src"], must_exist=True)
    dst = _resolve(args["dst"])
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    return {"src": str(src), "dst": str(dst)}


def t_fs_edit_block(args: dict) -> dict:
    """Targeted single-occurrence find/replace. Errors if `find` is missing or
    appears more than once (caller must disambiguate with surrounding context)."""
    path = _resolve(args["path"], must_exist=True)
    find = args["find"]
    replace = args["replace"]
    if not isinstance(find, str) or not isinstance(replace, str):
        raise ValueError("find and replace must be strings")
    text = path.read_text(encoding="utf-8")
    occurrences = text.count(find)
    if occurrences == 0:
        raise ValueError("find string not present")
    if occurrences > 1:
        raise ValueError(f"find string is ambiguous ({occurrences} matches) — add context")
    new_text = text.replace(find, replace, 1)
    path.write_text(new_text, encoding="utf-8")
    return {"path": str(path), "replaced": 1, "delta_bytes": len(new_text) - len(text)}


def t_code_search(args: dict) -> dict:
    """Substring/regex search across allowed roots. Returns up to `limit` hits."""
    pattern = args["pattern"]
    path = args.get("path")
    is_regex = bool(args.get("regex", False))
    case_insensitive = bool(args.get("ignore_case", True))
    limit = max(1, min(int(args.get("limit", 200)), 2000))
    file_glob = args.get("glob")

    roots: list[Path] = []
    if path:
        roots.append(_resolve(path, must_exist=True))
    else:
        for r in ALLOWED_PATHS:
            p = Path(r)
            if p.exists():
                roots.append(p)

    if is_regex:
        flags = re.IGNORECASE if case_insensitive else 0
        rx = re.compile(pattern, flags)
        def match(line: str) -> bool: return bool(rx.search(line))
    else:
        needle = pattern.lower() if case_insensitive else pattern
        def match(line: str) -> bool:
            hay = line.lower() if case_insensitive else line
            return needle in hay

    hits: list[dict] = []
    skipped_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache",
                    ".pytest_cache", "dist", "build", ".next", ".turbo"}
    for root in roots:
        if root.is_file():
            files_iter = [root]
        else:
            files_iter = []
            for r2, dirs, files in os.walk(root):
                dirs[:] = [d for d in dirs if d not in skipped_dirs]
                for f in files:
                    files_iter.append(Path(r2) / f)
        for fp in files_iter:
            if file_glob and not fp.match(file_glob):
                continue
            try:
                if fp.stat().st_size > READ_MAX_BYTES:
                    continue
                with fp.open("r", encoding="utf-8", errors="strict") as fh:
                    for ln, line in enumerate(fh, 1):
                        if match(line):
                            hits.append({"path": str(fp), "line": ln,
                                         "text": line.rstrip("\n")[:400]})
                            if len(hits) >= limit:
                                return {"pattern": pattern, "count": len(hits),
                                        "truncated": True, "hits": hits}
            except (UnicodeDecodeError, OSError):
                continue
    return {"pattern": pattern, "count": len(hits), "truncated": False, "hits": hits}


def t_proc_exec(args: dict) -> dict:
    """One-shot run of a NAMED command from the allowlist. No raw shell."""
    name = args["name"]
    if name not in NAMED_COMMANDS:
        raise KeyError(f"command {name!r} not in allowlist")
    extra = args.get("args") or []
    if not isinstance(extra, list) or not all(isinstance(x, str) for x in extra):
        raise ValueError("args must be list[str]")
    cwd_arg = args.get("cwd")
    cwd = str(_resolve(cwd_arg, must_exist=True)) if cwd_arg else None
    timeout = max(1, min(int(args.get("timeout", EXEC_TIMEOUT_DEFAULT)), EXEC_TIMEOUT_MAX))
    argv = list(NAMED_COMMANDS[name]) + list(extra)
    t0 = time.time()
    try:
        cp = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                            timeout=timeout, check=False)
    except subprocess.TimeoutExpired as e:
        return {"name": name, "argv": argv, "timed_out": True,
                "timeout_s": timeout, "stdout": (e.stdout or "")[-4000:],
                "stderr": (e.stderr or "")[-4000:]}
    return {"name": name, "argv": argv, "exit_code": cp.returncode,
            "elapsed_s": round(time.time() - t0, 3),
            "stdout": cp.stdout[-32000:], "stderr": cp.stderr[-32000:]}


def t_proc_start(args: dict) -> dict:
    name = args["name"]
    if name not in NAMED_COMMANDS:
        raise KeyError(f"command {name!r} not in allowlist")
    extra = args.get("args") or []
    if not isinstance(extra, list) or not all(isinstance(x, str) for x in extra):
        raise ValueError("args must be list[str]")
    cwd_arg = args.get("cwd")
    cwd = str(_resolve(cwd_arg, must_exist=True)) if cwd_arg else None
    argv = list(NAMED_COMMANDS[name]) + list(extra)
    proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, bufsize=1)
    sid = uuid.uuid4().hex[:12]
    sess = Session(sid, name, argv, proc)
    with SESSIONS_LOCK:
        _reap_dead_sessions()
        SESSIONS[sid] = sess
    return sess.info()


def t_proc_send(args: dict) -> dict:
    sid = args["session_id"]
    data = args.get("data", "")
    if not isinstance(data, str):
        raise ValueError("data must be a string")
    with SESSIONS_LOCK:
        sess = SESSIONS.get(sid)
    if not sess:
        raise KeyError(f"session {sid!r} not found")
    if sess.proc.stdin is None or sess.proc.poll() is not None:
        raise RuntimeError("session not accepting input")
    sess.proc.stdin.write(data)
    sess.proc.stdin.flush()
    return {"session_id": sid, "bytes_sent": len(data)}


def t_proc_read(args: dict) -> dict:
    sid = args["session_id"]
    with SESSIONS_LOCK:
        sess = SESSIONS.get(sid)
    if not sess:
        raise KeyError(f"session {sid!r} not found")
    out, err = sess.drain()
    info = sess.info()
    info.update({"stdout": out, "stderr": err})
    return info


def t_proc_stop(args: dict) -> dict:
    sid = args["session_id"]
    with SESSIONS_LOCK:
        sess = SESSIONS.pop(sid, None)
    if not sess:
        raise KeyError(f"session {sid!r} not found")
    if sess.proc.poll() is None:
        sess.proc.terminate()
        try:
            sess.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            sess.proc.kill()
            sess.proc.wait(timeout=2)
    out, err = sess.drain()
    info = sess.info()
    info.update({"stdout": out, "stderr": err, "stopped": True})
    return info


def t_proc_sessions(args: dict) -> dict:
    with SESSIONS_LOCK:
        _reap_dead_sessions()
        items = [s.info() for s in SESSIONS.values()]
    return {"count": len(items), "sessions": items}


def t_proc_list(args: dict) -> dict:
    """Read-only enumeration of system processes via /proc (Linux). No kill."""
    items: list[dict] = []
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return {"count": 0, "processes": [], "note": "no /proc on this platform"}
    for entry in sorted(os.listdir(proc_root)):
        if not entry.isdigit():
            continue
        pid_dir = proc_root / entry
        try:
            cmdline = (pid_dir / "cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="replace").strip()
            comm = (pid_dir / "comm").read_text().strip()
            st = pid_dir.stat()
            items.append({"pid": int(entry), "comm": comm, "cmdline": cmdline[:400], "uid": st.st_uid})
        except (OSError, PermissionError):
            continue
        if len(items) >= 1000:
            break
    return {"count": len(items), "processes": items}


def t_config_get(args: dict) -> dict:
    return {
        "server": SERVER_NAME, "version": SERVER_VERSION,
        "bind": f"{BIND_HOST}:{BIND_PORT}", "auth_required": bool(TOKEN),
        "allowed_paths": ALLOWED_PATHS,
        "named_commands": sorted(NAMED_COMMANDS.keys()),
        "limits": {
            "exec_timeout_default_s": EXEC_TIMEOUT_DEFAULT,
            "exec_timeout_max_s": EXEC_TIMEOUT_MAX,
            "read_max_bytes": READ_MAX_BYTES,
            "write_max_bytes": WRITE_MAX_BYTES,
        },
    }


# --- tool registry ----------------------------------------------------------


TOOLS: dict[str, tuple[str, callable, dict]] = {
    "fs.read":       ("Read a UTF-8 text file from an allowed path. Args: path, optional offset/limit (line-based).",
                      t_fs_read,
                      {"type": "object", "required": ["path"],
                       "properties": {"path": {"type": "string"},
                                      "offset": {"type": "integer", "minimum": 0},
                                      "limit": {"type": "integer", "minimum": 1},
                                      "encoding": {"type": "string"}}}),
    "fs.write":      ("Write a UTF-8 text file under an allowed path. Args: path, content, mode='rewrite'|'append'.",
                      t_fs_write,
                      {"type": "object", "required": ["path", "content"],
                       "properties": {"path": {"type": "string"},
                                      "content": {"type": "string"},
                                      "mode": {"type": "string", "enum": ["rewrite", "append"]}}}),
    "fs.list":       ("Recursive directory listing (depth <= 6). Args: path, optional depth (default 2).",
                      t_fs_list,
                      {"type": "object", "required": ["path"],
                       "properties": {"path": {"type": "string"},
                                      "depth": {"type": "integer", "minimum": 0, "maximum": 6}}}),
    "fs.info":       ("Stat a file or directory. Args: path.",
                      t_fs_info,
                      {"type": "object", "required": ["path"],
                       "properties": {"path": {"type": "string"}}}),
    "fs.mkdir":      ("Create a directory under an allowed path (mkdir -p).",
                      t_fs_mkdir,
                      {"type": "object", "required": ["path"],
                       "properties": {"path": {"type": "string"}}}),
    "fs.move":       ("Move/rename within allowed paths. Args: src, dst.",
                      t_fs_move,
                      {"type": "object", "required": ["src", "dst"],
                       "properties": {"src": {"type": "string"}, "dst": {"type": "string"}}}),
    "fs.edit_block": ("Single-occurrence find/replace in a text file. Errors if find is missing/ambiguous.",
                      t_fs_edit_block,
                      {"type": "object", "required": ["path", "find", "replace"],
                       "properties": {"path": {"type": "string"},
                                      "find": {"type": "string"},
                                      "replace": {"type": "string"}}}),
    "code.search":   ("Search files under allowed roots for a substring or regex. Args: pattern, optional path/glob/regex/ignore_case/limit.",
                      t_code_search,
                      {"type": "object", "required": ["pattern"],
                       "properties": {"pattern": {"type": "string"},
                                      "path": {"type": "string"},
                                      "glob": {"type": "string"},
                                      "regex": {"type": "boolean"},
                                      "ignore_case": {"type": "boolean"},
                                      "limit": {"type": "integer", "minimum": 1, "maximum": 2000}}}),
    "proc.exec":     ("One-shot run of a NAMED whitelisted command. Args: name, optional args[]/cwd/timeout.",
                      t_proc_exec,
                      {"type": "object", "required": ["name"],
                       "properties": {"name": {"type": "string"},
                                      "args": {"type": "array", "items": {"type": "string"}},
                                      "cwd": {"type": "string"},
                                      "timeout": {"type": "integer", "minimum": 1}}}),
    "proc.start":    ("Spawn a NAMED whitelisted command as a session. Returns session_id.",
                      t_proc_start,
                      {"type": "object", "required": ["name"],
                       "properties": {"name": {"type": "string"},
                                      "args": {"type": "array", "items": {"type": "string"}},
                                      "cwd": {"type": "string"}}}),
    "proc.send":     ("Write data to a session's stdin.",
                      t_proc_send,
                      {"type": "object", "required": ["session_id", "data"],
                       "properties": {"session_id": {"type": "string"}, "data": {"type": "string"}}}),
    "proc.read":     ("Drain buffered stdout/stderr from a session and return its info.",
                      t_proc_read,
                      {"type": "object", "required": ["session_id"],
                       "properties": {"session_id": {"type": "string"}}}),
    "proc.stop":     ("Terminate a session (SIGTERM, then SIGKILL after 5s).",
                      t_proc_stop,
                      {"type": "object", "required": ["session_id"],
                       "properties": {"session_id": {"type": "string"}}}),
    "proc.sessions": ("List active sessions started via proc.start.",
                      t_proc_sessions, {"type": "object", "properties": {}}),
    "proc.list":     ("Read-only enumeration of system processes (pid, comm, cmdline, uid). No kill.",
                      t_proc_list, {"type": "object", "properties": {}}),
    "config.get":    ("Return server config: bind, allowed paths, named commands, limits.",
                      t_config_get, {"type": "object", "properties": {}}),
}


def _tool_name(internal: str) -> str:
    return internal.replace(".", "_")


def _internal_from_tool_name(name: str) -> str | None:
    for k in TOOLS:
        if _tool_name(k) == name or k == name:
            return k
    return None


def _tools_list() -> list[dict]:
    return [{"name": _tool_name(k), "description": desc, "inputSchema": schema}
            for k, (desc, _fn, schema) in TOOLS.items()]


def _call_tool(name: str, args: dict) -> dict:
    internal = _internal_from_tool_name(name)
    if internal is None:
        raise KeyError(f"tool {name!r} not in whitelist")
    _desc, fn, _schema = TOOLS[internal]
    return fn(args or {})


# --- JSON-RPC dispatch ------------------------------------------------------


def dispatch(req: dict) -> dict | None:
    method = req.get("method")
    rid = req.get("id")
    params = req.get("params") or {}

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        }}
    if method == "notifications/initialized":
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": _tools_list()}}
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            out = _call_tool(name, args)
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": json.dumps(out, default=str, indent=2)}],
            }}
        except KeyError as e:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": str(e)}}
        except DeniedPath as e:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": f"denied: {e}"}}
        except (ValueError, FileNotFoundError, NotADirectoryError, IsADirectoryError, PermissionError) as e:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": f"{type(e).__name__}: {e}"}}
        except Exception as e:  # noqa: BLE001
            log(f"tool {name!r} crashed: {e}\n{traceback.format_exc()}")
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32603, "message": f"{type(e).__name__}: {e}"}}
    if method in ("resources/list", "prompts/list"):
        return {"jsonrpc": "2.0", "id": rid, "result": {method.split("/")[0]: []}}
    if rid is not None:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"method not found: {method}"}}
    return None


# --- HTTP handler -----------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    server_version = f"{SERVER_NAME}/{SERVER_VERSION}"

    def log_message(self, fmt, *args):
        pass

    def _check_auth(self) -> bool:
        if not TOKEN:
            return False
        hdr = self.headers.get("Authorization", "")
        if not hdr.startswith("Bearer "):
            return False
        return secrets.compare_digest(hdr[len("Bearer "):].strip(), TOKEN)

    def _json(self, code: int, body) -> None:
        data = json.dumps(body, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"ok": True, "server": SERVER_NAME, "version": SERVER_VERSION,
                              "auth_required": bool(TOKEN), "tools": len(TOOLS),
                              "allowed_paths": ALLOWED_PATHS,
                              "named_commands": sorted(NAMED_COMMANDS.keys()),
                              "sessions": len(SESSIONS)})
            return
        self.send_response(404); self.end_headers()

    def do_POST(self):
        if self.path != "/rpc":
            self.send_response(404); self.end_headers(); return
        if not self._check_auth():
            self._json(401, {"error": "unauthorized — missing or wrong bearer token"})
            return
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(n))
        except Exception as e:  # noqa: BLE001
            self._json(400, {"error": f"bad json: {e}"})
            return
        if isinstance(body, list):
            replies = [r for r in (dispatch(req) for req in body) if r is not None]
            self._json(200, replies)
        else:
            reply = dispatch(body)
            if reply is None:
                self.send_response(204); self.end_headers()
            else:
                self._json(200, reply)


_SHUTTING_DOWN = False


def _terminate_sessions() -> None:
    with SESSIONS_LOCK:
        for sid, sess in list(SESSIONS.items()):
            if sess.proc.poll() is None:
                try:
                    sess.proc.terminate()
                except Exception:
                    pass
        SESSIONS.clear()


def _graceful_shutdown(server: "ThreadingHTTPServer | None") -> None:
    global _SHUTTING_DOWN
    if _SHUTTING_DOWN:
        return
    _SHUTTING_DOWN = True
    log("shutdown: terminating child sessions")
    _terminate_sessions()
    if server is not None:
        log("shutdown: stopping HTTP server")
        threading.Thread(target=server.shutdown, name="commander-shutdown", daemon=True).start()


def main() -> int:
    if not TOKEN:
        log("FATAL: SYGNIF_PY_COMMANDER_TOKEN is not set — refusing to start.")
        log("       generate one with:  openssl rand -hex 32")
        log("       (the sygnif-commander launcher mints and persists one for you)")
        return 2
    log(f"binding {BIND_HOST}:{BIND_PORT} · {len(TOOLS)} tools · "
        f"{len(ALLOWED_PATHS)} allowed paths · {len(NAMED_COMMANDS)} named commands")
    srv = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)

    def _on_signal(signum, _frame):
        log(f"received signal {signum}")
        _graceful_shutdown(srv)

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    try:
        srv.serve_forever()
    finally:
        _graceful_shutdown(srv)
        log("exited cleanly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
