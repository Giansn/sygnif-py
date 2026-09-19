#!/usr/bin/env python3
"""SYGNIF py — the Nexus: labeled agent portals, from the terminal or the browser.

A portal is a persistent, individually-attachable tmux session named
``<type>-<label>`` (e.g. ``claude-thesis``, ``sygnif-recon``), so you can run many
of the same agent side by side and tell them apart. Detach and the portal keeps
running; SSH back in later and drop straight into it.

Two control planes over ONE launch table:

  terminal   nexus                     picker — table of live portals
             nexus <type> [label]      attach-or-create (label default: main)
             nexus new                 interactive: pick a type, give it a label
             nexus ls                  list live portals
             nexus -n <name>           plain shell portal (no agent)
             nexus spawn <type> [label] [dir]
                                       create WITHOUT attaching (no TTY needed)
             nexus prime <type> <label> "<first prompt>"
                                       create, then type a first prompt into it
             nexus send <name> "<text>"    type text into a live portal
             nexus preview <name> [n]      print a portal's screen
             nexus kill [-f] <name>    kill (REFUSES an attached portal; -f overrides)
             nexus rename <old> <newlabel> relabel a live portal
             nexus resume [type]       reopen a past agent conversation as a portal
             nexus types               what this machine can spawn, and from where
             nexus hub                 3-pane command center (list + preview + activity)
             nexus serve               the web board (below)
             nexus -h                  this help

  web        nexus serve  ->  http://127.0.0.1:8910
             Spawn/rename/kill from the page; attach in a shell with `nexus <name>`.
             Binds 127.0.0.1 only. To reach it from another machine, tunnel:
               ssh -N -L 8910:127.0.0.1:8910 <host>   then open http://localhost:8910

Portal types are DISCOVERED, never hardcoded to one person's machine:
  sygnif   -> the SYGNIF py seat (sygnif.sh next to this file, else `sygnif` on PATH)
  <agent>  -> any known agent CLI actually installed (claude, grok, codex, ...)
  shell    -> your login shell ($SHELL)
plus anything you declare yourself, which always wins:
  config.json / ~/.sygnif/sygnif-py.json ->  {"nexus": {"types": {"aider": "aider"}}}
  env                                   ->  SYGNIF_NEXUS_TYPES="aider=aider,ipython=ipython"

Both planes call the same functions here, so "what command starts a claude portal"
is written down exactly once — a split launch table is the classic way these two
views drift apart.

Requires tmux (Linux/macOS; on Windows run it inside WSL). Python stdlib only.
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("SYGNIF_NEXUS_PORT", "8910"))
BIND = os.environ.get("SYGNIF_NEXUS_BIND", "127.0.0.1")
HERE = os.path.dirname(os.path.abspath(__file__))
LABEL_RE = re.compile(r"[^a-zA-Z0-9_-]+")

# Small bits of state (recent dirs, hub selection) live under one overridable dir
# so nothing is written to a path baked in at build time.
STATE_DIR = os.path.expanduser(os.environ.get("SYGNIF_NEXUS_STATE", "~/.sygnif"))
DIR_HIST = os.path.join(STATE_DIR, "nexus-dirs")
HUB_SESS = os.environ.get("NEXUS_HUB_SESS", "nexus")
HUB_SEL = os.environ.get("NEXUS_HUB_SEL", os.path.join(STATE_DIR, "nexus-hub.sel"))

# Agent CLIs worth offering as a portal type IF they are installed. Presence on
# PATH is the test — an entry here is an offer, not a requirement, so the same
# build works on a machine that has none of them.
KNOWN_AGENTS = (
    "claude", "grok", "codex", "opencode", "aider", "cline",
    "gemini", "qwen", "devin", "cursor-agent", "goose",
)

# Conversation resume, per type. A type can only be resumed if we know BOTH how
# to list its past conversations and how to reopen one, so this is data, not code.
#   sessions: glob of transcript files, newest first
#   cmd:      launch command; {id} = session id (file stem), {dir} = its cwd
DEFAULT_RESUME = {
    "claude": {
        "sessions": "~/.claude/projects/*/*.jsonl",
        "cmd": "claude --resume {id}",
    },
}


def _cfg() -> dict:
    """Merged sygnif-py config, if the seat's loader is importable.

    The Nexus must also work standing alone (copied out on its own), so a missing
    or broken models.py is not fatal — it just means no config-declared types.
    """
    try:
        import models  # noqa: PLC0415 — optional, resolved at call time
        return models.load_config()
    except Exception:  # noqa: BLE001
        return {}


def build_launch_table() -> dict[str, str]:
    """Portal type -> launch command, from what this machine actually has.

    Later sources win, so an operator's own declaration always beats discovery.
    """
    launch: dict[str, str] = {}

    seat = os.path.join(HERE, "sygnif.sh")
    if os.path.isfile(seat):
        launch["sygnif"] = seat
    elif shutil.which("sygnif"):
        launch["sygnif"] = "sygnif"

    for agent in KNOWN_AGENTS:
        if shutil.which(agent):
            launch[agent] = agent

    launch["shell"] = os.environ.get("SHELL", "/bin/sh")

    nx = (_cfg().get("nexus") or {})
    for name, cmd in (nx.get("types") or {}).items():
        if isinstance(name, str) and isinstance(cmd, str) and name and cmd:
            launch[sanitize_label(name)] = cmd

    for pair in os.environ.get("SYGNIF_NEXUS_TYPES", "").split(","):
        if "=" in pair:
            name, _, cmd = pair.partition("=")
            name, cmd = name.strip(), cmd.strip()
            if name and cmd:
                launch[sanitize_label(name)] = cmd
    return launch


def resume_table() -> dict[str, dict]:
    """Type -> {sessions, cmd}; built-ins overridable from config."""
    table = {k: dict(v) for k, v in DEFAULT_RESUME.items()}
    for name, spec in ((_cfg().get("nexus") or {}).get("resume") or {}).items():
        if isinstance(spec, dict) and spec.get("sessions") and spec.get("cmd"):
            table[name] = dict(spec)
    return table


LAUNCH: dict[str, str] = {}
TYPES: list[str] = []


def refresh_types() -> None:
    """Rebuild the launch table. Called at start and after anything that could
    change it, so a long-lived hub picks up a newly installed agent."""
    global LAUNCH, TYPES
    LAUNCH = build_launch_table()
    TYPES = list(LAUNCH.keys())


# ---- tmux primitives -------------------------------------------------------

def tmux(*args: str, timeout: float = 10) -> tuple[int, str]:
    try:
        p = subprocess.run(["tmux", *args], capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:  # noqa: BLE001
        return 1, str(e)


def have_tmux() -> bool:
    return shutil.which("tmux") is not None


def running(name: str) -> bool:
    return tmux("has-session", "-t", f"={name}")[0] == 0


def attached(name: str) -> bool:
    rc, out = tmux("list-sessions", "-F", "#{session_name} #{session_attached}")
    if rc != 0:
        return False
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == name:
            return parts[1] not in ("0", "")
    return False


def pane_size(name: str) -> str:
    rc, out = tmux("list-panes", "-t", f"={name}", "-F", "#{pane_width}x#{pane_height}")
    return out.splitlines()[0].strip() if rc == 0 and out.strip() else "—"


# ---- portal model ----------------------------------------------------------

def sanitize_label(label: str) -> str:
    """tmux forbids '.' and ':' in session names; keep the rest tidy."""
    label = LABEL_RE.sub("-", (label or "").strip()).strip("-")
    return label or "main"


def classify(name: str) -> tuple[str, str] | None:
    """name -> (type, label) if it is a portal session, else None.

    A bare legacy session named exactly like a type counts as label "main", so an
    existing plain `claude` session is adopted instead of orphaned beside a new
    `claude-main`.
    """
    for t in sorted(TYPES, key=len, reverse=True):
        if name == t:
            return t, "main"
        if name.startswith(t + "-"):
            return t, name[len(t) + 1:]
    return None


def session_name(ptype: str, label: str) -> str:
    if label == "main" and running(ptype):
        return ptype
    return f"{ptype}-{label}"


def list_portals() -> list[dict]:
    rc, out = tmux("list-sessions", "-F",
                   "#{session_name}\t#{session_attached}\t#{session_created}")
    if rc != 0:
        return []
    portals = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name, att = parts[0], parts[1]
        c = classify(name)
        if not c:
            continue
        ptype, label = c
        portals.append({
            "name": name,
            "type": ptype,
            "label": label,
            "state": "attached" if att not in ("0", "") else "running",
            "size": pane_size(name),
            "created": parts[2] if len(parts) > 2 else "",
        })
    portals.sort(key=lambda p: (TYPES.index(p["type"]) if p["type"] in TYPES else 99, p["label"]))
    return portals


def scan() -> list[str]:
    return [p["name"] for p in list_portals()]


# ---- operations (one implementation, used by terminal AND web) -------------

def create_portal(ptype: str, label: str = "main", cwd: str | None = None,
                  prompt: str = "") -> dict:
    """Create a portal without attaching. Never relaunches a live session."""
    refresh_types()
    if ptype not in LAUNCH:
        return {"ok": False, "error": f"unknown type: {ptype} (have: {', '.join(TYPES)})"}
    label = sanitize_label(label)
    name = session_name(ptype, label)
    if running(name):
        return {"ok": True, "name": name, "note": "already running"}
    cwd = os.path.expanduser(cwd or "~")
    if not os.path.isdir(cwd):
        cwd = os.path.expanduser("~")
    rc, out = tmux("new-session", "-d", "-s", name, "-c", cwd)
    if rc != 0:
        return {"ok": False, "error": out.strip() or "tmux new-session failed"}
    tmux("send-keys", "-t", f"={name}:", LAUNCH[ptype], "C-m")
    if prompt:
        # The agent's TUI is not accepting input the instant the process starts;
        # hand the first prompt over after it has drawn itself.
        _delayed_send(name, prompt, delay=6)
    return {"ok": True, "name": name, "dir": cwd}


def _delayed_send(name: str, text: str, delay: int = 6) -> None:
    """Send text into a portal after `delay`s, without blocking the caller."""
    script = (
        f"import subprocess,time,sys; time.sleep({delay}); "
        f"n=sys.argv[1]; t=sys.argv[2]; "
        f"subprocess.run(['tmux','send-keys','-t',n+':','-l',t]); "
        f"subprocess.run(['tmux','send-keys','-t',n+':','C-m'])"
    )
    try:
        subprocess.Popen([sys.executable, "-c", script, f"={name}", text],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    except Exception:  # noqa: BLE001
        pass


def kill_portal(name: str, force: bool = False) -> dict:
    """Kill a portal. Refuses an ATTACHED one unless forced.

    This guard is the whole reason both planes share this function: a session
    someone is attached to may be a live console, and killing it cuts that
    session off mid-sentence. The web board used to be able to do that with one
    click while the terminal refused — same door, two locks, one of them open.
    """
    if not classify(name):
        return {"ok": False, "error": "not a portal session"}
    if not running(name):
        return {"ok": False, "error": f"no such session: {name}"}
    if attached(name) and not force:
        return {"ok": False, "attached": True,
                "error": f"REFUSING: '{name}' has an attached client (possibly a live "
                         f"console). If you are sure: nexus kill -f {name}"}
    rc, out = tmux("kill-session", "-t", f"={name}")
    return {"ok": True, "name": name} if rc == 0 else {"ok": False, "error": out.strip()}


def rename_portal(name: str, label: str) -> dict:
    """Relabel a live portal. Non-destructive: tmux keeps attached clients."""
    if not running(name):
        return {"ok": False, "error": f"no such session: {name}"}
    c = classify(name)
    newname = f"{c[0]}-{sanitize_label(label)}" if c else sanitize_label(label)
    rc, out = tmux("rename-session", "-t", f"={name}", newname)
    return {"ok": True, "name": newname} if rc == 0 else {"ok": False, "error": out.strip()}


def send_portal(name: str, text: str) -> dict:
    if not running(name):
        return {"ok": False, "error": f"no such session: {name}"}
    tmux("send-keys", "-t", f"={name}:", "-l", text)
    rc, out = tmux("send-keys", "-t", f"={name}:", "C-m")
    return {"ok": rc == 0, "error": out.strip()} if rc != 0 else {"ok": True, "name": name}


def capture_portal(name: str, lines: int = 40) -> str:
    """The last `lines` of a portal's screen.

    tmux returns the WHOLE pane including its trailing blank rows, so a tail of a
    quiet portal is pure whitespace — the content you wanted is scrolled off the
    top of the tail, not missing. Drop the trailing blanks first, then tail.
    """
    if not running(name):
        return f"no such session: {name}"
    rc, out = tmux("capture-pane", "-p", "-t", f"={name}:")
    if rc != 0:
        return out.strip()
    rows = out.splitlines()
    while rows and not rows[-1].strip():
        rows.pop()
    return "\n".join(rows[-lines:])


def enter_portal(name: str) -> int:
    """Attach, or switch when we are already inside tmux (can't nest)."""
    if not running(name):
        print(f"no such portal: {name}", file=sys.stderr)
        return 1
    if os.environ.get("TMUX"):
        return subprocess.call(["tmux", "switch-client", "-t", f"={name}"])
    return subprocess.call(["tmux", "attach", "-t", f"={name}"])


# ---- per-spawn directory chooser -------------------------------------------

def _recent_dirs(limit: int = 9) -> list[str]:
    try:
        with open(DIR_HIST, encoding="utf-8") as fh:
            seen, out = set(), []
            for line in reversed(fh.read().splitlines()):
                d = line.strip()
                if d and d not in seen and os.path.isdir(os.path.expanduser(d)):
                    seen.add(d)
                    out.append(d)
                if len(out) >= limit:
                    break
            return out
    except FileNotFoundError:
        return []
    except Exception:  # noqa: BLE001
        return []


def _remember_dir(d: str) -> None:
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(DIR_HIST, "a", encoding="utf-8") as fh:
            fh.write(d.rstrip("/") + "\n")
    except Exception:  # noqa: BLE001
        pass


def choose_dir(default: str | None = None) -> str:
    """Ask where a fresh portal should start. Non-TTY callers take the default,
    so automation never hangs waiting on a prompt nobody can answer."""
    default = os.path.expanduser(default or "~")
    if not sys.stdin.isatty():
        return default
    cur = default
    while True:
        try:
            subs = sorted(d for d in os.listdir(cur)
                          if not d.startswith(".") and os.path.isdir(os.path.join(cur, d)))
        except Exception:  # noqa: BLE001
            subs = []
        recents = _recent_dirs()
        print(f"\n  \033[1;36mstart where?\033[0m  \033[2m{cur}\033[0m")
        for i, d in enumerate(subs[:26]):
            print(f"    {chr(ord('a') + i)}) {d}/")
        for i, d in enumerate(recents):
            print(f"    {i + 1}) \033[2m{d}\033[0m")
        print("    \033[2m⏎ = use this dir · .. = up · ~ = home · /path = jump · "
              "+name = create · q = cancel\033[0m")
        try:
            pick = input("  dir> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        if pick == "":
            _remember_dir(cur)
            return cur
        if pick in ("q", "Q"):
            return default
        if pick == "..":
            cur = os.path.dirname(cur.rstrip("/")) or "/"
            continue
        if pick == "~":
            cur = os.path.expanduser("~")
            continue
        if pick.startswith("+"):
            new = os.path.join(cur, sanitize_label(pick[1:]))
            try:
                os.makedirs(new, exist_ok=True)
                cur = new
            except Exception as e:  # noqa: BLE001
                print(f"  cannot create: {e}")
            continue
        if pick.startswith(("/", "~")) or os.path.isdir(os.path.expanduser(pick)):
            cand = os.path.expanduser(pick)
            if os.path.isdir(cand):
                cur = cand
            else:
                print(f"  not a directory: {cand}")
            continue
        if len(pick) == 1 and pick.isalpha() and 0 <= ord(pick) - ord("a") < len(subs[:26]):
            cur = os.path.join(cur, subs[ord(pick) - ord("a")])
            continue
        if pick.isdigit() and 1 <= int(pick) <= len(recents):
            cur = os.path.expanduser(recents[int(pick) - 1])
            continue
        print(f"  no such choice: {pick}")


# ---- attach-or-create ------------------------------------------------------

def portal(ptype: str, label: str = "main", prompt: str = "") -> int:
    """The main verb: attach the portal if it is up, otherwise create and enter."""
    refresh_types()
    if ptype not in LAUNCH:
        print(f"unknown portal type: {ptype} (have: {', '.join(TYPES)})", file=sys.stderr)
        return 1
    label = sanitize_label(label)
    name = session_name(ptype, label)
    if running(name):
        return enter_portal(name)          # already up — never relaunch the agent
    r = create_portal(ptype, label, choose_dir(), prompt)
    if not r.get("ok"):
        print(r.get("error", "failed"), file=sys.stderr)
        return 1
    return enter_portal(r["name"])


def shell_portal(name: str) -> int:
    """A plain shell portal — no agent, any name."""
    name = sanitize_label(name)
    if not running(name):
        tmux("new-session", "-d", "-s", name, "-c", choose_dir())
    return enter_portal(name)


# ---- picker ----------------------------------------------------------------

def _palette(ptype: str) -> str:
    """Stable colour per type without naming anyone's favourite agents."""
    colours = ("36", "32", "38;5;208", "34", "38;5;203", "35", "33", "38;5;141")
    return colours[sum(ptype.encode()) % len(colours)]


def _print_table(portals: list[dict]) -> None:
    if not portals:
        print("  (no live portals)\n")
        return
    print("  \033[2m#   type       label            state       size\033[0m")
    for i, p in enumerate(portals, 1):
        state = ("\033[33m● attached\033[0m" if p["state"] == "attached"
                 else "\033[32m● running\033[0m ")
        col = _palette(p["type"])
        print(f"  {i:<3} \033[{col}m{p['type']:<10}\033[0m {p['label']:<16} "
              f"{state}  {p['size']}")
    print()


def menu() -> int:
    refresh_types()
    portals = list_portals()
    host = os.uname().nodename if hasattr(os, "uname") else "this host"
    print(f"\033[1;36m  ⬡ SYGNIF nexus\033[0m — portals on {host}\n")
    _print_table(portals)
    print(f"  \033[2mtypes: {', '.join(TYPES)}\033[0m")
    print("  n) new labeled portal   k) kill   e) rename   r) resume")
    print("  p) prime a portal with a first prompt      s) plain shell")
    print("  h) hub (3-pane center)  w) web board       q) quit")
    try:
        choice = input("\nchoose> ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return 0
    if choice in ("", "q", "Q"):
        return 0
    if choice in ("n", "N"):
        return new_flow()
    if choice in ("k", "K"):
        return kill_flow(portals)
    if choice in ("e", "E"):
        return rename_flow(portals)
    if choice in ("r", "R"):
        return resume_flow()
    if choice in ("p", "P"):
        return prime_flow()
    if choice in ("s", "S"):
        return shell_portal(input("shell name> ").strip() or "shell")
    if choice in ("h", "H"):
        return hub()
    if choice in ("w", "W"):
        return serve()
    if choice in TYPES:
        return portal(choice, input(f"label for {choice} [main]> ").strip() or "main")
    if choice.isdigit() and 1 <= int(choice) <= len(portals):
        return enter_portal(portals[int(choice) - 1]["name"])
    print(f"no such option: {choice}", file=sys.stderr)
    return 1


def _pick_type() -> str | None:
    print("\n  pick a type:")
    for i, t in enumerate(TYPES, 1):
        print(f"    {i}) {t}  \033[2m{LAUNCH[t]}\033[0m")
    try:
        pick = input("type> ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if pick.isdigit() and 1 <= int(pick) <= len(TYPES):
        return TYPES[int(pick) - 1]
    if pick in LAUNCH:
        return pick
    print(f"no such type: {pick}", file=sys.stderr)
    return None


def new_flow() -> int:
    t = _pick_type()
    if not t:
        return 1
    label = input("label> ").strip()
    if not label:
        print("a label is required for a new portal", file=sys.stderr)
        return 1
    return portal(t, label)


def prime_flow() -> int:
    t = _pick_type()
    if not t:
        return 1
    label = input("label> ").strip() or "main"
    first = input("first prompt> ").strip()
    return portal(t, label, prompt=first)


def _select(portals: list[dict], what: str) -> str | None:
    if not portals:
        print(f"no live portals to {what}", file=sys.stderr)
        return None
    _print_table(portals)
    try:
        sel = input(f"{what} which (# or name)> ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if not sel:
        return None
    if sel.isdigit() and 1 <= int(sel) <= len(portals):
        return portals[int(sel) - 1]["name"]
    return sel


def kill_flow(portals: list[dict] | None = None) -> int:
    portals = portals if portals is not None else list_portals()
    name = _select(portals, "kill")
    if not name:
        return 0
    r = kill_portal(name)
    print(f"killed: {name}" if r.get("ok") else r.get("error"),
          file=sys.stdout if r.get("ok") else sys.stderr)
    return 0 if r.get("ok") else 1


def rename_flow(portals: list[dict] | None = None) -> int:
    portals = portals if portals is not None else list_portals()
    name = _select(portals, "rename")
    if not name:
        return 0
    label = input("new label> ").strip()
    if not label:
        print("new label required", file=sys.stderr)
        return 1
    r = rename_portal(name, label)
    print(f"renamed: {name} -> {r['name']}" if r.get("ok") else r.get("error"),
          file=sys.stdout if r.get("ok") else sys.stderr)
    return 0 if r.get("ok") else 1


# ---- resume a past conversation -------------------------------------------

def _session_rows(ptype: str, spec: dict, limit: int) -> list[dict]:
    """Newest conversations for a type: (id, when, cwd, first line)."""
    rows = []
    for path in glob.glob(os.path.expanduser(spec["sessions"])):
        try:
            st = os.stat(path)
        except OSError:
            continue
        rows.append({"path": path, "mtime": st.st_mtime,
                     "id": os.path.splitext(os.path.basename(path))[0]})
    rows.sort(key=lambda r: r["mtime"], reverse=True)
    rows = rows[:limit]
    for r in rows:
        r["cwd"], r["first"] = "", ""
        try:
            with open(r["path"], encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    try:
                        rec = json.loads(line)
                    except Exception:  # noqa: BLE001
                        continue
                    if not r["cwd"] and isinstance(rec.get("cwd"), str):
                        r["cwd"] = rec["cwd"]
                    if not r["first"]:
                        msg = rec.get("message") or {}
                        if rec.get("type") == "user" or msg.get("role") == "user":
                            c = msg.get("content") if isinstance(msg, dict) else None
                            if isinstance(c, list):
                                c = " ".join(str(b.get("text", "")) for b in c
                                             if isinstance(b, dict))
                            if isinstance(c, str) and c.strip():
                                r["first"] = " ".join(c.split())[:70]
                    if r["cwd"] and r["first"]:
                        break
        except Exception:  # noqa: BLE001
            pass
    return rows


def resume_flow(ptype: str | None = None, limit: int = 15) -> int:
    refresh_types()
    table = resume_table()
    usable = {t: s for t, s in table.items() if t in LAUNCH}
    if not usable:
        print("no resumable portal type on this machine.", file=sys.stderr)
        print("declare one in config.json:  "
              '{"nexus": {"resume": {"<type>": {"sessions": "<glob>", "cmd": "... {id}"}}}}',
              file=sys.stderr)
        return 1
    if ptype is None:
        ptype = next(iter(usable)) if len(usable) == 1 else (_pick_type() or "")
    if ptype not in usable:
        print(f"type '{ptype}' has no resume recipe (have: {', '.join(usable)})", file=sys.stderr)
        return 1
    spec = usable[ptype]
    rows = _session_rows(ptype, spec, limit)
    if not rows:
        print(f"no past {ptype} conversations found under {spec['sessions']}", file=sys.stderr)
        return 1
    live = set(scan())
    print(f"\n  \033[1;36mrecent {ptype} conversations\033[0m")
    for i, r in enumerate(rows, 1):
        when = time.strftime("%m-%d %H:%M", time.localtime(r["mtime"]))
        mark = " \033[33m(open)\033[0m" if f"{ptype}-{r['id'][:8]}" in live else ""
        print(f"    {i:<3} \033[2m{when}\033[0m  {r['first'] or '(no prompt found)'}{mark}")
        if r["cwd"]:
            print(f"        \033[2m{r['cwd']}\033[0m")
    try:
        sel = input("\nresume which> ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return 0
    if not (sel.isdigit() and 1 <= int(sel) <= len(rows)):
        return 0
    r = rows[int(sel) - 1]
    label = sanitize_label(r["id"][:8])
    name = f"{ptype}-{label}"
    cmd = spec["cmd"].format(id=r["id"], dir=r["cwd"] or os.path.expanduser("~"))
    if not running(name):
        tmux("new-session", "-d", "-s", name,
             "-c", r["cwd"] if r["cwd"] and os.path.isdir(r["cwd"]) else os.path.expanduser("~"))
        tmux("send-keys", "-t", f"={name}:", cmd, "C-m")
    return enter_portal(name)


# ---- hub: 3-pane command center -------------------------------------------

def hub() -> int:
    """Build the layout, run a helper in each pane, enter it."""
    if not have_tmux():
        print("the hub needs tmux.", file=sys.stderr)
        return 1
    os.makedirs(os.path.dirname(HUB_SEL) or ".", exist_ok=True)
    if running(HUB_SESS):
        return enter_portal(HUB_SESS)
    me = os.path.abspath(__file__)
    py = sys.executable or "python3"
    home = os.path.expanduser("~")
    rc, p0 = tmux("new-session", "-d", "-s", HUB_SESS, "-c", home,
                  "-x", "220", "-y", "50", "-P", "-F", "#{pane_id}")
    if rc != 0:
        print(p0.strip() or "could not create the hub session", file=sys.stderr)
        return 1
    p0 = p0.strip()
    _, p1 = tmux("split-window", "-h", "-t", p0, "-c", home, "-P", "-F", "#{pane_id}")
    p1 = p1.strip()
    _, p2 = tmux("split-window", "-v", "-t", p1, "-c", home, "-P", "-F", "#{pane_id}")
    p2 = p2.strip()
    tmux("resize-pane", "-t", p0, "-x", "34")
    tmux("resize-pane", "-t", p2, "-y", "12")
    env = f"NEXUS_HUB_SESS={HUB_SESS} NEXUS_HUB_SEL='{HUB_SEL}'"
    for pane, sub in ((p0, "_hub-list"), (p1, "_hub-preview"), (p2, "_hub-activity")):
        tmux("send-keys", "-t", pane, f"{env} exec {py} '{me}' {sub}", "C-m")
    tmux("select-pane", "-t", p0)
    tmux("set-option", "-t", f"={HUB_SESS}", "mouse", "on")
    if os.environ.get("NEXUS_HUB_NO_ENTER"):
        print(HUB_SESS)
        return 0
    return enter_portal(HUB_SESS)


def _read_key(timeout: float = 1.0) -> str | None:
    """One keypress, or None when the timeout expires so the pane can redraw."""
    import select
    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        if select.select([sys.stdin], [], [], timeout)[0]:
            ch = sys.stdin.read(1)
            if ch == "\x1b":  # swallow escape sequences (arrow keys)
                if select.select([sys.stdin], [], [], 0.01)[0]:
                    sys.stdin.read(2)
                return "\x1b"
            return ch
        return None
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _hub_draw(portals: list[dict], idx: int, mode: str, prompt: str, buf: str) -> None:
    host = os.uname().nodename if hasattr(os, "uname") else ""
    out = ["\033[H", f"\033[1;36m ⬡ nexus\033[0m \033[2m· {host}\033[0m\033[K\n",
           f"\033[2m ↻ live · {len(portals)} portals\033[0m\033[K\n\033[K\n"]
    if not portals:
        out.append(" \033[2m(no portals — press n)\033[0m\033[K\n")
    for i, p in enumerate(portals):
        col = _palette(p["type"])
        dot = "\033[33m●\033[0m" if p["state"] == "attached" else "\033[32m●\033[0m"
        if i == idx:
            out.append(f"\033[7m ▸ \033[{col}m{p['type']:<7}\033[0m\033[7m "
                       f"{p['label']:<12} \033[0m {dot}\033[K\n")
        else:
            out.append(f"   \033[{col}m{p['type']:<7}\033[0m {p['label']:<12} {dot}\033[K\n")
    out.append("\033[K\n")
    if mode == "nav":
        out.append(" \033[2mj/k move · ⏎ switch · n new · x kill\033[0m\033[K\n"
                   " \033[2mr rename · q quit\033[0m\033[K\n")
    else:
        out.append(f" \033[1;36m{prompt}\033[0m{buf}\033[K\n"
                   " \033[2mEsc cancel\033[0m\033[K\n")
    out.append("\033[J")
    sys.stdout.write("".join(out))
    sys.stdout.flush()


def hub_list() -> int:
    """Left pane: live list plus non-blocking input modes.

    Every mode runs through the same 1s-timeout read loop, so the refresh never
    stalls and Esc always escapes — you cannot get trapped in a sub-prompt.
    """
    refresh_types()
    idx, mode, buf, prompt = 0, "nav", "", ""
    ntype = ""
    sys.stdout.write("\033[?25l")
    try:
        while True:
            portals = list_portals()
            if idx >= len(portals):
                idx = max(0, len(portals) - 1)
            try:
                with open(HUB_SEL, "w", encoding="utf-8") as fh:
                    fh.write(portals[idx]["name"] + "\n" if portals else "")
            except Exception:  # noqa: BLE001
                pass
            _hub_draw(portals, idx, mode, prompt, buf)
            key = _read_key(1.0)
            if key is None:
                continue
            if mode == "nav":
                if key in ("q", "Q"):
                    return 0
                if key in ("j", "\x0e") and portals:
                    idx = min(idx + 1, len(portals) - 1)
                elif key in ("k", "\x10") and portals:
                    idx = max(idx - 1, 0)
                elif key in ("\r", "\n") and portals:
                    tmux("switch-client", "-t", f"={portals[idx]['name']}")
                elif key in ("n", "N"):
                    mode, buf, prompt, ntype = "newtype", "", "type (1..%d)> " % len(TYPES), ""
                elif key in ("x", "X") and portals:
                    kill_portal(portals[idx]["name"])   # attached portals survive
                elif key in ("r", "R") and portals:
                    mode, buf, prompt = "rename", "", "new label> "
                continue
            # --- text entry modes
            if key == "\x1b":
                mode, buf = "nav", ""
                continue
            if key in ("\r", "\n"):
                text, was = buf.strip(), mode
                mode, buf = "nav", ""
                if was == "newtype":
                    if text.isdigit() and 1 <= int(text) <= len(TYPES):
                        ntype = TYPES[int(text) - 1]
                    elif text in LAUNCH:
                        ntype = text
                    if ntype:
                        mode, prompt = "newlabel", f"label for {ntype}> "
                    continue
                if was == "newlabel":
                    create_portal(ntype, text or "main")
                    ntype = ""
                    continue
                if was == "rename" and portals:
                    rename_portal(portals[idx]["name"], text)
                    continue
                continue
            if key in ("\x7f", "\b"):
                buf = buf[:-1]
            elif key.isprintable():
                buf += key
    except KeyboardInterrupt:
        return 0
    finally:
        sys.stdout.write("\033[?25h\033[2J\033[H")
        sys.stdout.flush()


def hub_preview() -> int:
    """Right-top pane: live screen of whatever the list pane has selected."""
    try:
        while True:
            sel = ""
            try:
                with open(HUB_SEL, encoding="utf-8") as fh:
                    sel = fh.read().strip()
            except Exception:  # noqa: BLE001
                pass
            rows = (os.get_terminal_size().lines - 2) if sys.stdout.isatty() else 22
            sys.stdout.write("\033[H")
            if sel and running(sel):
                sys.stdout.write(f"\033[1;36m▸ preview\033[0m \033[2m{sel}\033[0m\033[K\n"
                                 f"\033[2m────────────\033[0m\033[K\n")
                body = capture_portal(sel, rows)
                sys.stdout.write("".join(l + "\033[K\n" for l in body.splitlines()))
            else:
                sys.stdout.write("\033[1;36m▸ preview\033[0m\033[K\n\033[K\n"
                                 " \033[2m(no portal selected)\033[0m\033[K\n")
            sys.stdout.write("\033[J")
            sys.stdout.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        return 0


def hub_activity() -> int:
    """Right-bottom pane: a passive tail.

    There is no generic "the log" on an arbitrary machine, so the default is the
    portal roster itself. Point it anywhere with NEXUS_HUB_ACTIVITY_CMD.
    """
    cmd = os.environ.get("NEXUS_HUB_ACTIVITY_CMD")
    if cmd:
        return subprocess.call(cmd, shell=True)
    print("\033[1;36m▸ activity\033[0m \033[2m(portals · set NEXUS_HUB_ACTIVITY_CMD to "
          "tail your own)\033[0m", flush=True)
    try:
        while True:
            rc, out = tmux("list-sessions", "-F",
                           "#{session_name}  #{session_attached}  #{session_windows}w")
            print(time.strftime("  %H:%M:%S"), flush=True)
            print(out.rstrip() if rc == 0 else "  (no tmux sessions)", flush=True)
            time.sleep(5)
    except KeyboardInterrupt:
        return 0


# ---- web plane -------------------------------------------------------------

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
            refresh_types()
            self._json(200, {"host": os.uname().nodename, "types": TYPES,
                             "portals": list_portals()})
        elif path == "/api/preview":
            import urllib.parse
            q = urllib.parse.parse_qs(self.path.partition("?")[2])
            name = (q.get("name") or [""])[0]
            self._json(200, {"name": name, "screen": capture_portal(name, 60)})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/")
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n)) if n else {}
        except Exception as e:  # noqa: BLE001
            self._json(400, {"ok": False, "error": f"bad json: {e}"})
            return
        if path == "/api/portals":
            self._json(200, create_portal(body.get("type", ""), body.get("label", ""),
                                          body.get("dir"), body.get("prompt", "")))
        elif path == "/api/kill":
            # force is opt-in over the wire too: the page cannot cut a live console
            # off by accident just because it is a different front end.
            self._json(200, kill_portal(body.get("name", ""), bool(body.get("force"))))
        elif path == "/api/rename":
            self._json(200, rename_portal(body.get("name", ""), body.get("label", "")))
        elif path == "/api/send":
            self._json(200, send_portal(body.get("name", ""), body.get("text", "")))
        else:
            self._json(404, {"ok": False, "error": "not found"})


def serve() -> int:
    refresh_types()
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"SYGNIF Nexus: http://{BIND}:{PORT}  (host={os.uname().nodename}, "
          f"types: {', '.join(TYPES)})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


# ---- dispatch --------------------------------------------------------------

def _help() -> int:
    print(__doc__.strip())
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not have_tmux():
        print("SYGNIF Nexus needs tmux (portals ARE tmux sessions).", file=sys.stderr)
        print("Install it: apt/dnf/pkg/brew install tmux — on Windows, run inside WSL.",
              file=sys.stderr)
        return 127
    refresh_types()
    cmd = argv[0] if argv else "menu"
    rest = argv[1:]

    if cmd in ("-h", "--help", "help"):
        return _help()
    if cmd in ("ls", "-l", "--list"):
        portals = list_portals()
        _print_table(portals)
        return 0
    if cmd == "types":
        for t in TYPES:
            print(f"  {t:<12} {LAUNCH[t]}")
        return 0
    if cmd in ("-n", "--shell"):
        if not rest:
            print("usage: nexus -n <name>", file=sys.stderr)
            return 1
        return shell_portal(rest[0])
    if cmd == "new":
        return new_flow()
    if cmd == "menu":
        return menu()
    if cmd == "spawn":
        if not rest:
            print("usage: nexus spawn <type> [label] [dir]", file=sys.stderr)
            return 1
        r = create_portal(rest[0], rest[1] if len(rest) > 1 else "main",
                          rest[2] if len(rest) > 2 else None)
        print(r.get("name") if r.get("ok") else r.get("error"),
              file=sys.stdout if r.get("ok") else sys.stderr)
        return 0 if r.get("ok") else 1
    if cmd == "prime":
        if len(rest) < 3:
            print('usage: nexus prime <type> <label> "<first prompt>"', file=sys.stderr)
            return 1
        r = create_portal(rest[0], rest[1], None, " ".join(rest[2:]))
        print(r.get("name") if r.get("ok") else r.get("error"),
              file=sys.stdout if r.get("ok") else sys.stderr)
        return 0 if r.get("ok") else 1
    if cmd == "send":
        if len(rest) < 2:
            print('usage: nexus send <name> "<text>"', file=sys.stderr)
            return 1
        r = send_portal(rest[0], " ".join(rest[1:]))
        if not r.get("ok"):
            print(r.get("error"), file=sys.stderr)
            return 1
        return 0
    if cmd == "preview":
        if not rest:
            print("usage: nexus preview <name> [lines]", file=sys.stderr)
            return 1
        print(capture_portal(rest[0], int(rest[1]) if len(rest) > 1 else 40))
        return 0
    if cmd == "kill":
        force = False
        args = list(rest)
        if args and args[0] in ("-f", "--force"):
            force, args = True, args[1:]
        if not args:
            print("usage: nexus kill [-f] <name>", file=sys.stderr)
            return 1
        r = kill_portal(args[0], force)
        print(f"killed: {args[0]}" if r.get("ok") else r.get("error"),
              file=sys.stdout if r.get("ok") else sys.stderr)
        return 0 if r.get("ok") else 1
    if cmd == "rename":
        if len(rest) < 2:
            print("usage: nexus rename <old> <newlabel>", file=sys.stderr)
            return 1
        r = rename_portal(rest[0], rest[1])
        print(f"renamed: {rest[0]} -> {r['name']}" if r.get("ok") else r.get("error"),
              file=sys.stdout if r.get("ok") else sys.stderr)
        return 0 if r.get("ok") else 1
    if cmd == "resume":
        return resume_flow(rest[0] if rest else None)
    if cmd == "hub":
        return hub()
    if cmd == "_hub-list":
        return hub_list()
    if cmd == "_hub-preview":
        return hub_preview()
    if cmd == "_hub-activity":
        return hub_activity()
    if cmd in ("serve", "web", "up"):
        return serve()
    if cmd in LAUNCH:
        return portal(cmd, rest[0] if rest else "main")
    # A live portal can be named directly: `nexus claude-thesis`
    if running(cmd) and classify(cmd):
        return enter_portal(cmd)
    print(f"unknown target '{cmd}'. types: {', '.join(TYPES)}", file=sys.stderr)
    print("modes: new spawn prime send preview kill rename resume hub serve types "
          f"(plain shell: nexus -n {cmd})", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
