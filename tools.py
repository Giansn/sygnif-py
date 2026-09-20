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
    container = os.environ.get("SYGNIF_PY_KALI_CONTAINER", "sygnif-kali")
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
    container = os.environ.get("SYGNIF_PY_KALI_CONTAINER", "sygnif-kali")
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
    hosting|scout|analyzer|exploiter|reporter). No network needed; use this when the van has no signal."""
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
                "postexploit, report, webapp, wpsec, hosting, scout, analyzer, exploiter, "
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
    container = os.environ.get("SYGNIF_PY_KALI_CONTAINER", "sygnif-kali")
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
    "playbook": {
        "desc": ("Return the offline pentest methodology shipped with the seat — the kill-chain "
                 "checklist and the role modes. section=<phase or role> for one part. Needs no "
                 "network; use it when the van has no signal."),
        "args": {"section": "optional: recon|enum|vuln|exploit|postexploit|report|webapp|wpsec|hosting|scout|analyzer|exploiter|reporter"},
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
