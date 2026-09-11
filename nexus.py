#!/usr/bin/env python3
"""SYGNIF py — the Nexus: a web portal board for your agent sessions.

A tiny stdlib HTTP server (no deps) in front of tmux. Every tmux session named
<type> or <type>-<label> is a "portal": a live agent (or plain shell) you can
see, spawn, rename and close from the browser, and attach to from any terminal
with `tmux attach -t <name>`.

Binds 127.0.0.1 only by default. To reach it from another machine, use an SSH
tunnel:  ssh -N -L 8910:127.0.0.1:8910 <host>  then open http://localhost:8910.

    python3 nexus.py                     # http://127.0.0.1:8910
    SYGNIF_NEXUS_PORT=9999 python3 nexus.py

Portal types (what a card spawns) are discovered from what is installed:
  sygnif  -> the SYGNIF py seat (sygnif.sh next to this file)
  claude  -> the `claude` CLI, if on PATH
  shell   -> your login shell ($SHELL)
Add your own with SYGNIF_NEXUS_TYPES, comma-separated name=command pairs:
  SYGNIF_NEXUS_TYPES="aider=aider,ipython=ipython" python3 nexus.py

Requires tmux (Linux/macOS; on Windows run it inside WSL).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("SYGNIF_NEXUS_PORT", "8910"))
BIND = os.environ.get("SYGNIF_NEXUS_BIND", "127.0.0.1")
HERE = os.path.dirname(os.path.abspath(__file__))
LABEL_RE = re.compile(r"[^a-zA-Z0-9_-]+")


def build_launch_table() -> dict[str, str]:
    """Portal type -> launch command, from what this machine actually has."""
    launch: dict[str, str] = {}
    seat = os.path.join(HERE, "sygnif.sh")
    if os.path.isfile(seat):
        launch["sygnif"] = seat
    elif shutil.which("sygnif"):
        launch["sygnif"] = "sygnif"
    if shutil.which("claude"):
        launch["claude"] = "claude"
    launch["shell"] = os.environ.get("SHELL", "/bin/sh")
    # user extensions / overrides: SYGNIF_NEXUS_TYPES="name=command,name2=cmd2"
    for pair in os.environ.get("SYGNIF_NEXUS_TYPES", "").split(","):
        if "=" in pair:
            name, _, cmd = pair.partition("=")
            name, cmd = name.strip(), cmd.strip()
            if name and cmd:
                launch[LABEL_RE.sub("-", name)] = cmd
    return launch


LAUNCH = build_launch_table()
TYPES = list(LAUNCH.keys())


def tmux(*args: str) -> tuple[int, str]:
    try:
        p = subprocess.run(["tmux", *args], capture_output=True, text=True, timeout=10)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return 1, str(e)


def sanitize_label(label: str) -> str:
    label = LABEL_RE.sub("-", (label or "").strip()).strip("-")
    return label or "main"


def classify(name: str) -> tuple[str, str] | None:
    """name -> (type, label) if it is a portal session, else None."""
    for t in TYPES:
        if name == t:
            return t, "main"
        if name.startswith(t + "-"):
            return t, name[len(t) + 1:]
    return None


def session_name(ptype: str, label: str, live: set[str]) -> str:
    """Bare legacy session reused when label == main and it already exists."""
    if label == "main" and ptype in live:
        return ptype
    return f"{ptype}-{label}"


def list_portals() -> list[dict]:
    rc, out = tmux("list-sessions", "-F", "#{session_name}\t#{session_attached}\t#{session_created}")
    if rc != 0:
        return []
    portals = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name, attached = parts[0], parts[1]
        created = parts[2] if len(parts) > 2 else ""
        c = classify(name)
        if not c:
            continue
        ptype, label = c
        rc2, size = tmux("list-panes", "-t", f"={name}", "-F", "#{pane_width}x#{pane_height}")
        size = size.splitlines()[0].strip() if rc2 == 0 and size.strip() else "—"
        portals.append({
            "name": name,
            "type": ptype,
            "label": label,
            "state": "attached" if attached not in ("0", "") else "running",
            "size": size,
            "created": created,
        })
    portals.sort(key=lambda p: (TYPES.index(p["type"]) if p["type"] in TYPES else 9, p["label"]))
    return portals


def create_portal(ptype: str, label: str) -> dict:
    if ptype not in LAUNCH:
        return {"ok": False, "error": f"unknown type: {ptype}"}
    label = sanitize_label(label)
    live = {p["name"] for p in list_portals()}
    name = session_name(ptype, label, live)
    if name in live:
        return {"ok": True, "name": name, "note": "already running"}
    rc, out = tmux("new-session", "-d", "-s", name, "-c", os.path.expanduser("~"))
    if rc != 0:
        return {"ok": False, "error": out.strip() or "tmux new-session failed"}
    # boot the agent inside the fresh session so it is live when attached
    tmux("send-keys", "-t", f"={name}:", LAUNCH[ptype], "C-m")
    return {"ok": True, "name": name}


def kill_portal(name: str) -> dict:
    if not classify(name):
        return {"ok": False, "error": "not a portal session"}
    # never kill a portal someone is attached to — detach first, then kill
    for p in list_portals():
        if p["name"] == name and p["state"] == "attached":
            return {"ok": False, "error": "portal is attached — detach from it first (Ctrl-b d)"}
    rc, out = tmux("kill-session", "-t", f"={name}")
    return {"ok": rc == 0, "error": out.strip()} if rc != 0 else {"ok": True}


def rename_portal(name: str, label: str) -> dict:
    c = classify(name)
    if not c:
        return {"ok": False, "error": "not a portal session"}
    ptype, _ = c
    newname = f"{ptype}-{sanitize_label(label)}"
    rc, out = tmux("rename-session", "-t", f"={name}", newname)
    return {"ok": rc == 0, "name": newname} if rc == 0 else {"ok": False, "error": out.strip()}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj):
        self._send(code, json.dumps(obj).encode(), "application/json")

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/") or "/"
        if path == "/":
            try:
                with open(os.path.join(HERE, "static", "nexus.html"), "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except FileNotFoundError:
                self._send(500, b"static/nexus.html missing", "text/plain")
        elif path == "/api/health":
            self._json(200, {"ok": True, "host": os.uname().nodename, "port": PORT})
        elif path == "/api/portals":
            self._json(200, {"host": os.uname().nodename, "types": TYPES, "portals": list_portals()})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/")
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n)) if n else {}
        except Exception as e:
            self._json(400, {"ok": False, "error": f"bad json: {e}"})
            return
        if path == "/api/portals":
            self._json(200, create_portal(body.get("type", ""), body.get("label", "")))
        elif path == "/api/kill":
            self._json(200, kill_portal(body.get("name", "")))
        elif path == "/api/rename":
            self._json(200, rename_portal(body.get("name", ""), body.get("label", "")))
        else:
            self._json(404, {"ok": False, "error": "not found"})


def main():
    if not shutil.which("tmux"):
        print("SYGNIF Nexus needs tmux (it manages portals as tmux sessions).", file=sys.stderr)
        print("Install it: apt/dnf/brew install tmux — on Windows, run inside WSL.", file=sys.stderr)
        sys.exit(1)
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"SYGNIF Nexus: http://{BIND}:{PORT}  (host={os.uname().nodename}, "
          f"types: {', '.join(TYPES)})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
