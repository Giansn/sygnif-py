#!/usr/bin/env python3
"""SYGNIF py — Centre (the knot point).

One endpoint, a registry of neurons, every generic capability the seat can ask
for behind a single dispatch. This is the self-contained sibling of the SYGNIF
stack's Centre: instead of a private trading/chain/intel surface, it ships a
small set of generic, read-mostly neurons that any host has:

  * sys.state       — OS, uptime, load, memory, disk, python, listening ports,
                      and (if present) the operator's systemd --user units.
  * sys.procs       — a snapshot of running processes (top by RSS).
  * note.write      — append a line to the engagement/working journal.
  * note.read       — read the tail of the journal.
  * knowledge.search— grep the operator's local knowledge directory.
  * knowledge.read  — read a file from the knowledge directory.

The registry is the extension point. Drop a `~/.sygnif/centre-neurons.py` (or a
`centre_neurons.py` next to this file) that defines `register(NEURONS)` and adds
your own neurons — that is how you grow Centre into your own knot point without
touching this file. See the bottom of this module for the neuron contract.

Transport: HTTP. Two shapes, both accepted on POST /rpc:
  * simple:   {"tool": "<neuron>", "args": {...}}
  * JSON-RPC: {"jsonrpc":"2.0","id":1,"method":"tools/call",
               "params":{"name":"<neuron>","arguments":{...}}}
GET /health  — liveness + neuron count.   GET /tools — the neuron catalog.

Auth: optional bearer token from SYGNIF_PY_CENTRE_TOKEN. Default bind is
127.0.0.1, so it is loopback-only unless you deliberately widen the bind AND
set a token. If you set SYGNIF_PY_CENTRE_BIND to a non-loopback address the
server REFUSES to start without a token.

Run:  python3 centre.py           (or the sygnif-centre launcher)
Env:  SYGNIF_PY_CENTRE_BIND (127.0.0.1)  SYGNIF_PY_CENTRE_PORT (9100)
      SYGNIF_PY_CENTRE_TOKEN ("")         SYGNIF_PY_KNOWLEDGE (~/.sygnif/knowledge)
      SYGNIF_PY_JOURNAL (~/.sygnif/sygnif-py-journal.md)
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import os
import platform
import secrets
import shutil
import subprocess
import sys
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SERVER_NAME = "sygnif-py-centre"
SERVER_VERSION = "1.0.0"
PROTOCOL_VERSION = "2024-11-05"

BIND_HOST = os.environ.get("SYGNIF_PY_CENTRE_BIND", "127.0.0.1")
BIND_PORT = int(os.environ.get("SYGNIF_PY_CENTRE_PORT", "9100"))
TOKEN = os.environ.get("SYGNIF_PY_CENTRE_TOKEN", "").strip()

SEAT_DIR = os.path.dirname(os.path.abspath(__file__))
KNOWLEDGE_DIR = Path(
    os.path.expanduser(os.environ.get("SYGNIF_PY_KNOWLEDGE", "~/.sygnif/knowledge"))
)
JOURNAL = Path(
    os.path.expanduser(os.environ.get("SYGNIF_PY_JOURNAL", "~/.sygnif/sygnif-py-journal.md"))
)
START_TIME = time.time()


def log(msg: str) -> None:
    sys.stderr.write(f"[{SERVER_NAME}] {msg}\n")
    sys.stderr.flush()


def _ok(**kw) -> dict:
    d = {"ok": True}
    d.update(kw)
    return d


def _err(msg: str) -> dict:
    return {"ok": False, "error": msg}


# --- generic neurons --------------------------------------------------------


def _cmd(argv: list[str], timeout: int = 8) -> str:
    """Best-effort helper: run a read-only command, return stdout or ''."""
    try:
        cp = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return (cp.stdout or "").strip()
    except Exception:
        return ""


def n_sys_state(args: dict) -> dict:
    uname = platform.uname()
    state: dict = {
        "host": uname.node,
        "os": f"{uname.system} {uname.release}",
        "machine": uname.machine,
        "python": platform.python_version(),
        "time": datetime.datetime.now().isoformat(timespec="seconds"),
        "centre_uptime_s": round(time.time() - START_TIME, 1),
    }
    # load + boot-relative uptime (Linux/macOS)
    try:
        state["loadavg"] = [round(x, 2) for x in os.getloadavg()]
    except (OSError, AttributeError):
        pass
    # disk of HOME
    try:
        du = shutil.disk_usage(str(Path.home()))
        state["disk_home"] = {
            "total_gb": round(du.total / 2**30, 1),
            "used_gb": round(du.used / 2**30, 1),
            "free_gb": round(du.free / 2**30, 1),
        }
    except Exception:
        pass
    # memory (Linux /proc/meminfo)
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        try:
            info = {}
            for line in meminfo.read_text().splitlines():
                k, _, v = line.partition(":")
                info[k.strip()] = v.strip()
            total = int(info.get("MemTotal", "0 kB").split()[0])
            avail = int(info.get("MemAvailable", "0 kB").split()[0])
            state["mem"] = {
                "total_mb": round(total / 1024),
                "available_mb": round(avail / 1024),
                "used_pct": round(100 * (total - avail) / total) if total else None,
            }
        except Exception:
            pass
    # listening ports (ss, best effort)
    if shutil.which("ss"):
        ports = []
        for line in _cmd(["ss", "-ltnH"], timeout=5).splitlines():
            parts = line.split()
            if len(parts) >= 4:
                local = parts[3]
                port = local.rsplit(":", 1)[-1]
                if port.isdigit():
                    ports.append(int(port))
        state["listening_ports"] = sorted(set(ports))[:50]
    # systemd --user units (best effort)
    if shutil.which("systemctl"):
        units = []
        out = _cmd(["systemctl", "--user", "list-units", "--type=service",
                    "--state=running", "--no-legend", "--no-pager"], timeout=6)
        for line in out.splitlines():
            name = line.split()[0] if line.split() else ""
            if name.endswith(".service"):
                units.append(name)
        if units:
            state["systemd_user_running"] = units[:60]
    return _ok(state=state)


def n_sys_procs(args: dict) -> dict:
    top = int(args.get("top", 15) or 15)
    procs: list[dict] = []
    proc_root = Path("/proc")
    if proc_root.is_dir():
        page = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
        for entry in os.listdir(proc_root):
            if not entry.isdigit():
                continue
            pd = proc_root / entry
            try:
                comm = (pd / "comm").read_text().strip()
                statm = (pd / "statm").read_text().split()
                rss_mb = round(int(statm[1]) * page / 2**20, 1) if len(statm) > 1 else 0
                procs.append({"pid": int(entry), "comm": comm, "rss_mb": rss_mb})
            except (OSError, ValueError):
                continue
        procs.sort(key=lambda p: p["rss_mb"], reverse=True)
        return _ok(count=len(procs), top=procs[:top])
    # non-Linux fallback: ps
    out = _cmd(["ps", "-eo", "pid,rss,comm", "--sort=-rss"], timeout=6) or \
        _cmd(["ps", "-Ao", "pid,rss,comm"], timeout=6)
    for line in out.splitlines()[1:top + 1]:
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit():
            procs.append({"pid": int(parts[0]),
                          "rss_mb": round(int(parts[1]) / 1024, 1) if parts[1].isdigit() else None,
                          "comm": parts[2]})
    return _ok(count=len(procs), top=procs)


def n_note_write(args: dict) -> dict:
    text = str(args.get("text", "")).strip()
    if not text:
        return _err("note.write: empty text")
    try:
        JOURNAL.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with JOURNAL.open("a", encoding="utf-8") as f:
            f.write(f"- [{ts}] {text}\n")
    except Exception as e:  # noqa: BLE001
        return _err(f"note.write: {e}")
    return _ok(journal=str(JOURNAL))


def n_note_read(args: dict) -> dict:
    tail = int(args.get("tail", 40) or 40)
    if not JOURNAL.is_file():
        return _ok(journal=str(JOURNAL), lines=[], note="journal is empty")
    try:
        lines = JOURNAL.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as e:  # noqa: BLE001
        return _err(f"note.read: {e}")
    return _ok(journal=str(JOURNAL), lines=lines[-tail:], total=len(lines))


def n_knowledge_search(args: dict) -> dict:
    query = str(args.get("query", "")).strip()
    if not query:
        return _err("knowledge.search: empty query")
    limit = int(args.get("limit", 30) or 30)
    if not KNOWLEDGE_DIR.is_dir():
        return _ok(dir=str(KNOWLEDGE_DIR), count=0, hits=[],
                   note=f"no knowledge dir yet — create {KNOWLEDGE_DIR} and add notes")
    needle = query.lower()
    hits: list[dict] = []
    for root, dirs, files in os.walk(KNOWLEDGE_DIR):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fn in files:
            fp = Path(root) / fn
            try:
                if fp.stat().st_size > 2 * 2**20:
                    continue
                for ln, line in enumerate(fp.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if needle in line.lower():
                        hits.append({"path": str(fp), "line": ln, "text": line.strip()[:300]})
                        if len(hits) >= limit:
                            return _ok(dir=str(KNOWLEDGE_DIR), count=len(hits), hits=hits, truncated=True)
            except (OSError, UnicodeDecodeError):
                continue
    return _ok(dir=str(KNOWLEDGE_DIR), count=len(hits), hits=hits, truncated=False)


def n_knowledge_read(args: dict) -> dict:
    rel = str(args.get("path", "")).strip()
    if not rel:
        return _err("knowledge.read: empty path")
    target = (KNOWLEDGE_DIR / rel).expanduser()
    try:
        target = target.resolve()
        base = KNOWLEDGE_DIR.resolve()
    except Exception as e:  # noqa: BLE001
        return _err(f"knowledge.read: {e}")
    if not (str(target) == str(base) or str(target).startswith(str(base) + os.sep)):
        return _err("knowledge.read: path escapes the knowledge directory")
    if not target.is_file():
        return _err(f"knowledge.read: not a file: {target}")
    try:
        content = target.read_text(encoding="utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        return _err(f"knowledge.read: {e}")
    return _ok(path=str(target), chars=len(content), content=content[:20000])


# --- neuron registry --------------------------------------------------------

# name -> {domain, description, schema (arg -> hint), func}
NEURONS: dict[str, dict] = {
    "sys.state": {
        "domain": "system",
        "description": "Structured snapshot of THIS host: os, uptime, load, memory, disk, python, listening ports, running user services.",
        "schema": {},
        "func": n_sys_state,
    },
    "sys.procs": {
        "domain": "system",
        "description": "Running processes on this host, heaviest by memory first.",
        "schema": {"top": "how many to return (default 15)"},
        "func": n_sys_procs,
    },
    "note.write": {
        "domain": "journal",
        "description": "Append a timestamped line to the working journal.",
        "schema": {"text": "the note to record"},
        "func": n_note_write,
    },
    "note.read": {
        "domain": "journal",
        "description": "Read the tail of the working journal.",
        "schema": {"tail": "how many trailing lines (default 40)"},
        "func": n_note_read,
    },
    "knowledge.search": {
        "domain": "knowledge",
        "description": "Search the operator's local knowledge directory for a substring.",
        "schema": {"query": "text to search for", "limit": "max hits (default 30)"},
        "func": n_knowledge_search,
    },
    "knowledge.read": {
        "domain": "knowledge",
        "description": "Read a file (by path relative to the knowledge dir) from the knowledge directory.",
        "schema": {"path": "path relative to the knowledge directory"},
        "func": n_knowledge_read,
    },
}


def _load_plugins() -> None:
    """Let the operator extend NEURONS from a drop-in file."""
    for path in (
        os.path.join(SEAT_DIR, "centre_neurons.py"),
        os.path.expanduser("~/.sygnif/centre-neurons.py"),
    ):
        if not os.path.isfile(path):
            continue
        ns: dict = {}
        try:
            with open(path, encoding="utf-8") as fh:
                exec(compile(fh.read(), path, "exec"), ns)  # noqa: S102 - operator's own file
            if callable(ns.get("register")):
                ns["register"](NEURONS)
                log(f"loaded neuron plugin: {path}")
        except Exception as e:  # noqa: BLE001
            log(f"plugin {path} failed to load: {e}")


def run_neuron(name: str, args: dict) -> dict:
    """Dispatch a neuron by name. Never raises — errors come back as {ok:false}."""
    neuron = NEURONS.get(name)
    if not neuron:
        # tolerate underscore form (sys_state -> sys.state)
        alt = name.replace("_", ".", 1)
        neuron = NEURONS.get(alt)
    if not neuron:
        return _err(f"unknown neuron '{name}'. available: {', '.join(sorted(NEURONS))}")
    try:
        return neuron["func"](args or {})
    except Exception as e:  # noqa: BLE001
        log(f"neuron {name!r} crashed: {e}\n{traceback.format_exc()}")
        return _err(f"neuron '{name}' raised: {type(e).__name__}: {e}")


def catalog() -> list[dict]:
    return [{"name": n, "domain": v.get("domain", ""),
             "description": v.get("description", ""),
             "args": v.get("schema", {})}
            for n, v in sorted(NEURONS.items())]


# --- HTTP handler -----------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    server_version = f"{SERVER_NAME}/{SERVER_VERSION}"

    def log_message(self, fmt, *args):
        pass

    def _check_auth(self) -> bool:
        if not TOKEN:
            return True  # loopback-only default; startup guards non-loopback binds
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
                              "auth_required": bool(TOKEN), "neurons": len(NEURONS)})
            return
        if self.path == "/tools":
            if not self._check_auth():
                self._json(401, {"error": "unauthorized"}); return
            self._json(200, {"neurons": catalog()})
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
        # JSON-RPC shape
        if isinstance(body, dict) and body.get("method"):
            method = body["method"]
            rid = body.get("id")
            params = body.get("params") or {}
            if method == "initialize":
                self._json(200, {"jsonrpc": "2.0", "id": rid, "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}}})
                return
            if method == "tools/list":
                tools = [{"name": c["name"], "description": c["description"],
                          "inputSchema": {"type": "object",
                                          "properties": {k: {"type": "string", "description": v}
                                                         for k, v in c["args"].items()},
                                          "additionalProperties": True}}
                         for c in catalog()]
                self._json(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": tools}})
                return
            if method == "tools/call":
                name = params.get("name")
                out = run_neuron(name, params.get("arguments") or {})
                self._json(200, {"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": json.dumps(out, default=str, indent=2)}]}})
                return
            self._json(200, {"jsonrpc": "2.0", "id": rid,
                             "error": {"code": -32601, "message": f"method not found: {method}"}})
            return
        # simple shape
        if isinstance(body, dict) and "tool" in body:
            out = run_neuron(str(body["tool"]), body.get("args") or {})
            self._json(200, out)
            return
        self._json(400, {"error": "expected {tool,args} or a JSON-RPC method body"})


def _bind_is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost",)


def main() -> int:
    _load_plugins()
    if not _bind_is_loopback(BIND_HOST) and not TOKEN:
        log(f"FATAL: binding non-loopback {BIND_HOST} without SYGNIF_PY_CENTRE_TOKEN — refusing to start.")
        log("       set a token (openssl rand -hex 32) or bind 127.0.0.1.")
        return 2
    log(f"binding {BIND_HOST}:{BIND_PORT} · {len(NEURONS)} neurons · "
        f"auth={'on' if TOKEN else 'off (loopback)'}")
    srv = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.shutdown()
        log("exited cleanly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
