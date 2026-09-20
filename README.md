# SYGNIF py

A tiny, dependency-free **SYGNIF seat** in Python — the generic cousin of SYGNIF pi.
It's an agent loop over **any OpenAI-compatible chat endpoint**: the model calls
tools by emitting a fenced `` ```tool `` block, the seat runs the tool on your
machine and feeds the result back, and it loops until the model answers.

No private models are baked in. Out of the box the default model is **Claude
Fable 5.1** on your own **Claude Pro/Max subscription** (via the official `claude`
CLI): the first time you run `sygnif`, it walks you through login and sets up a
pentest workspace. Prefer no login? Switch to a **free public OpenRouter model**
with `/model openrouter-free`, or add any other OpenAI-compatible endpoint.

## Install

**Linux / macOS**

```sh
curl -fsSL https://raw.githubusercontent.com/Giansn/sygnif-py/main/dist/install.sh | sh
```

**Windows (PowerShell)**

```powershell
irm https://raw.githubusercontent.com/Giansn/sygnif-py/main/dist/install.ps1 | iex
```

(Or host the four files in `dist/` yourself — any static host works — and set
`SYGNIF_PY_BASE_URL` before piping the installer.)

## First run — just type `sygnif`

The default model is **Claude Fable 5.1** on your Claude Pro/Max subscription. The
first launch is fully guided — you don't need to install anything by hand first:

```sh
sygnif                       # first run: installs prerequisites, logs you in, preps a workspace
```

That one-time onboarding:

0. **installs the prerequisites the package can't bundle** — the `claude` CLI
   (via `npm`, or the official installer, offering to add Node.js if needed) and
   `tmux` (for the `nexus` portal board) — each opt-in and only if missing. Turn
   this off with `SYGNIF_PY_BOOTSTRAP=0`;
1. runs `claude setup-token` so Fable 5.1 bills to your Pro/Max plan (not the
   pay-per-use API) — you can skip and run `sygnif login` later;
2. creates `~/sygnif-pentest/` with a `SCOPE.md` authorization reminder;
3. reports which common pentest tools (`nmap`, `curl`, `dig`, …) are on your box,
   and **offers to install the ones you're missing** (`nikto`, `gobuster`, `sqlmap`,
   `hydra`, `dnsutils`, …) via your package manager — `apt`/`brew`/`dnf`/`pacman`,
   skippable, needs `sudo`. Set `SYGNIF_PY_INSTALL_TOOLS=0` to turn this off;
4. drops you into the **pentest** preset, ready for your first authorized target.

It runs only once (gated by `~/.sygnif/.sygnif-py-initialized`; set
`SYGNIF_PY_FIRSTRUN=0` to skip it entirely, or delete the marker to run it again).

**Prefer a free model with no login?** In the seat, switch anytime:

```sh
/model openrouter-free       # then: export OPENROUTER_API_KEY=sk-or-...  (free key)
```

Free OpenRouter slugs rotate; if it 404s, pick a current one from
<https://openrouter.ai/models?max_price=0> and set its `id` in your config.

Both need **Python 3.8+** on PATH and nothing else — the seat uses only the
standard library. The installer unpacks to `~/.sygnif-py` and puts a `sygnif`
launcher on your PATH.

Run it:

```sh
sygnif                      # REPL on the default preset
sygnif --preset chat        # chat-only preset (no shell/file tools)
sygnif --preset dev         # development mode (build -> prove loop)
sygnif --preset ops         # ops mode (host state via the Centre)
sygnif "list my home dir"   # one-shot
sygnif --confirm            # ask before every shell / write_file / dev step
```

The install also puts two companion services on your PATH:

```sh
sygnif-centre               # the knot point — host state, notes, knowledge
sygnif-commander            # the hands — sandboxed, allowlisted fs/exec
```

## The three pieces

SYGNIF py ships the generic core of the SYGNIF architecture — a **seat**, a
**Centre**, and a **commander** — each self-contained and usable on its own.

### Seat (`sygnif`)
The agent loop. Talks to any OpenAI-compatible model, calls tools, loops until it
answers. This is what you run day to day.

Over a terminal it renders the **pix UI**: the model's reply streams token by
token, each turn opens with a `── turn N · HH:MM:SS ──` rule, and a dim status
line under the `❯` prompt shows where you stand —
`Σ <model> · ctx <used>/<window> <pct>% · ~<tps> tps · <n> turns`
(context occupancy and throughput come from the endpoint's own usage report when
it sends one, else a char estimate). Tool calls show as clean `→ tool(args)` /
`← result` lines instead of raw JSON. It's on automatically when stdout is a TTY;
a pipe gets plain text with no escape codes. Turn it off with `SYGNIF_PY_PIX=0`,
and colour follows `NO_COLOR`.

REPL commands: `/preset` `/model` `/models` `/tools` `/reset` `/help` `/quit`.

### Centre (`sygnif-centre`) — the knot point
One local HTTP endpoint (`:9100`) fronting a registry of **neurons** — small
capabilities behind a single dispatch. Ships generic, read-mostly neurons:

| neuron | what it returns |
|---|---|
| `sys.state` | host snapshot: os, uptime, load, memory, disk, listening ports, running user services |
| `sys.procs` | processes, heaviest by memory first |
| `note.write` / `note.read` | the working journal |
| `knowledge.search` / `knowledge.read` | grep/read your local notes dir (`~/.sygnif/knowledge`) |

Grow it: drop a `~/.sygnif/centre-neurons.py` defining `register(NEURONS)` and add
your own neurons. The seat reaches a running Centre with the **`centre`** tool
(used by the `ops` preset). Default bind is loopback; binding a non-loopback
address without `SYGNIF_PY_CENTRE_TOKEN` is refused.

### Commander (`sygnif-commander`) — the hands
A JSON-RPC HTTP endpoint (`:9110`) for **sandboxed, allowlisted** work on a host:
`fs_read`/`fs_write`/`fs_list`, `code_search`, and `proc_exec` (named commands
only — no raw shell). Two gates, both default-deny: every path must sit under an
allowed root, and exec only runs commands you've named. It **fails closed**: no
bearer token, no start. The launcher mints and persists a token on first run
(`~/.sygnif/sygnif-py-commander.env`); `source` it before `sygnif` and the seat's
**`commander`** tool can drive it.

### Development (`--preset dev`)
Development is a mode of the seat, not a separate service. The `dev` preset adds
the **`dev_apply_and_test`** tool: it writes your file(s) and runs a check/build
command in one step, reporting PASS/FAIL — so a change is never "done" until its
test actually ran. Work small, prove each step.

### Web & WordPress security (`--preset webdev`)
For a developer testing their **own** sites, hosting and WordPress (record the
authorization in `SCOPE.md` first). It's a web-focused slice of the pentest
toolset — drive `wpscan`, `nuclei`, `nikto`, `sqlmap`, `whatweb`, `wafw00f`,
`ffuf`/`feroxbuster`, `httpx`, `sslscan`/`testssl.sh`, `subfinder`/`amass` through
the `shell`/`kali` tools, and read the concrete checklists with the playbook:

```
/preset webdev
playbook section=webapp     # own web app: content discovery, headers, cookies, injection
playbook section=wpsec      # WordPress: wpscan enumerate, xmlrpc, REST user enum, hardening
playbook section=hosting    # server: exposed ports, TLS, SPF/DKIM/DMARC, subdomain takeover
```

Install the lighter web toolset (instead of the multi-GB full kill-chain):

```sh
SYGNIF_PY_KALI_METAPACKAGE=kali-tools-web sygnif kali-setup
```

`wpscan`'s CVE data needs a free [WPScan API token](https://wpscan.com/api) —
pass it with `--api-token <TOK>`. Same rule as always: only your own targets,
and every finding backed by a reproducible request/response.

### Full engagement (`--preset redteam`)
For an authorized red-team engagement. Structured, **auth-gated** wrappers around the
standard full-power tools — `recon`, `nuclei`, `wpscan`, `msf` (Metasploit),
`exploit_search` (searchsploit), `bruteforce` (hydra), `crack` (hashcat/john),
`postexploit` (linpeas, local enum only), `wifi_capture`/`wifi_crack` (hcxdumptool +
hashcat). **Every offensive tool refuses without a `target` and an `authorization`
attestation**, and is confined to `~/sygnif-pentest/SCOPE.md` when it lists targets.
No mass targeting, no persistence, no evasion — authorized scope only. Read
`playbook section=redteam` for the tool map, and install the tools with
`sygnif kali-setup` (or run inside the `sygnif-kali` container).

## Desk — chat + workflows in your browser

`sygnif-desk` starts a small web dashboard so you can use the same models from a
browser instead of the terminal:

```sh
sygnif-desk                     # serves http://127.0.0.1:8899
```

Open <http://127.0.0.1:8899>. It's **the same zero-dependency deal** as the rest
of SYGNIF py — pure Python standard library, no pip install, no venv, no build
step. It gives you:

* **Chat** over any model in your config (the provider picker lists them). Replies
  keep generating server-side even if you close the tab, then reattach when you
  return.
* **Workflows** — save and re-run multi-step prompts.
* State is stored as plain JSON files under `~/.sygnif/desk`.

Knobs (all optional):

| env var | default | what it does |
|---|---|---|
| `SYGNIF_DESK_PORT` | `8899` | port to serve on |
| `SYGNIF_DESK_HOST` | `127.0.0.1` | bind address — keep it loopback unless you know what you're doing |
| `SYGNIF_DESK_EXEC` | *off* | set to `1` to let the model run shell commands on this machine from the Desk (off by default) |
| `OPENROUTER_API_KEY` | — | your free OpenRouter key for the default provider |

> **Safety:** the Desk binds to loopback (`127.0.0.1`) so only your own machine
> can reach it, and it will **not** run shell commands unless you explicitly set
> `SYGNIF_DESK_EXEC=1`. Don't expose it to a public address.

## Nexus — labeled portals for your agent sessions

A **portal** is a persistent, individually-attachable tmux session named
`<type>-<label>` (e.g. `sygnif-thesis`, `claude-recon`), so you can run many of
the same agent side by side and tell them apart. Detach and it keeps running;
SSH back in tomorrow and drop straight into it.

Two front ends, one launch table: the `nexus` command in your terminal, and a web
board in the browser. Install tmux first (`apt/dnf/pkg/brew install tmux`; on
Windows run inside WSL) — portals *are* tmux sessions.

### From the terminal — `nexus`

```sh
nexus                          # picker: table of live portals, choose one
nexus claude thesis            # attach-or-create the claude-thesis portal
nexus new                      # interactive: pick a type, give it a label
nexus ls                       # list live portals
nexus types                    # what this machine can spawn, and from where
nexus hub                      # 3-pane command center (list + preview + activity)
nexus -h                       # full help
```

Fresh spawns ask **where to start** with a visual directory chooser: `Enter` takes
the current dir, `a`..`z` drill into a subdir, `1`..`9` jump to a recent one, `..`
goes up, `+name` creates one. Non-TTY callers skip it and take `~`, so scripts
never hang on a prompt nobody can answer.

Scripting and automation (no TTY required):

```sh
nexus spawn claude recon ~/work      # create WITHOUT attaching
nexus prime claude recon "read the scope file first"
                                    # create, then type a first prompt into it
nexus send claude-recon "status?"    # type text into a live portal
nexus preview claude-recon 40        # print its screen
nexus rename claude-recon audit      # relabel (keeps attached clients)
nexus kill claude-audit              # refuses if attached; -f overrides
nexus resume                         # reopen a past conversation as a portal
```

`nexus resume` needs to know how to list and reopen a type's past conversations,
so it is data rather than code — it ships knowing `claude`, and you can teach it
any agent:

```json
{"nexus": {"resume": {"myagent": {"sessions": "~/.myagent/**/*.jsonl",
                                  "cmd": "myagent --resume {id}"}}}}
```

### From the browser — `sygnif-nexus`

```sh
sygnif-nexus                   # serves http://127.0.0.1:8910
```

Pick a type, give the portal a label, hit **spawn** — a detached session starts
with that agent already running. Attaching stays a terminal action: cards hand you
`nexus <name>` to run. Working on a remote box? Don't expose the port, tunnel to
it: `ssh -N -L 8910:127.0.0.1:8910 <host>`, then open `http://localhost:8910`.

### From inside the seat — `/nexus`

```
/nexus                    list live portals
/nexus claude thesis      open one
/nexus kill claude-thesis close one
```

### Portal types are discovered, not hardcoded

`sygnif` (the seat itself), `shell` (your login shell), and any known agent CLI
actually installed — `claude`, `grok`, `codex`, `opencode`, `aider`, `cline`,
`gemini`, `qwen`, `devin`, `cursor-agent`, `goose`. Declare your own, which always
wins, in `config.json` or `~/.sygnif/sygnif-py.json`:

```json
{"nexus": {"types": {"aider": "aider --model sonnet", "ipython": "ipython3"}}}
```

...or for one run, via env: `SYGNIF_NEXUS_TYPES="aider=aider,ipython=ipython"`.

Knobs (all optional):

| env var | default | what it does |
|---|---|---|
| `SYGNIF_NEXUS_PORT` | `8910` | port the web board serves on |
| `SYGNIF_NEXUS_BIND` | `127.0.0.1` | bind address — keep it loopback |
| `SYGNIF_NEXUS_TYPES` | — | extra portal types, `name=command,name2=command2` |
| `SYGNIF_NEXUS_STATE` | `~/.sygnif` | where recent dirs / hub state are kept |
| `NEXUS_HUB_ACTIVITY_CMD` | — | what the hub's activity pane tails |

> **Safety:** the web board binds to loopback only, and **both** front ends refuse
> to kill a portal someone is attached to — that session may be a live console,
> and killing it cuts the person off mid-sentence. Pass `-f` (or `{"force": true}`)
> when you really mean it. Both planes call the same functions, so the terminal and
> the page cannot drift into disagreeing about what a portal is or who may close
> one. Zero dependencies: pure Python standard library, plus tmux.

## Models — bring your own

Four models ship listed:

| model | what it is | to use |
|---|---|---|
| `fable` *(default)* | **Claude Fable 5.1** on your Claude Pro/Max subscription via the official `claude` CLI | first run of `sygnif`, or `sygnif login` (needs the claude CLI) |
| `claude` | any other model on your subscription (`sonnet`/`opus`/`haiku`/full id) | `sygnif login` (needs the claude CLI) |
| `openrouter-free` | a free public OpenRouter slug — no login, just a free key | `/model openrouter-free` + `export OPENROUTER_API_KEY=...` |
| `inkling` | ThinkingMachines Inkling 256k on a local bridge (`:9223`) | run the bridge yourself |

Beyond those the seat is model-agnostic — anything that speaks
`/v1/chat/completions` works: OpenAI, OpenRouter (paid), a local **Ollama** or
**LM Studio**, `llama.cpp --server`, etc. The `claude` model is special: it has
`"provider": "claude-cli"` and shells out to the `claude` CLI (no OAuth secrets in
config; usage bills to your subscription).

Edit `config.json` (in the install dir) or, better, create `~/.sygnif/sygnif-py.json`
with the same shape — it's merged over the shipped config, so upgrades won't
clobber it:

```json
{
  "models": {
    "local": { "id": "llama3.1", "base_url": "http://127.0.0.1:11434/v1", "api_key_env": null, "context": 32768, "max_tokens": 4096 },
    "gpt":   { "id": "gpt-4o-mini", "base_url": "https://api.openai.com/v1", "api_key_env": "OPENAI_API_KEY", "context": 128000, "max_tokens": 4096 }
  },
  "default_preset": "assistant",
  "presets": {
    "assistant": { "model": "local", "tools": ["shell", "read_file", "write_file", "note"], "focus": "..." }
  }
}
```

**API keys are never stored in the config** — `api_key_env` is the *name* of an
environment variable the seat reads at runtime (e.g. `export OPENAI_API_KEY=...`).

Switch models live in the REPL with `/model <key>`, list them with `/models`.

## Tools

Built in: `shell` (run a command here), `read_file`, `write_file`, `note` (append
to a journal), `dev_apply_and_test` (write + prove), `centre` (ask a running
Centre for a neuron), `commander` (drive a running commander). A preset chooses
which tools are active.

Add your own tools without touching the core: copy `custom_tools.py.example` to
`custom_tools.py` (or `~/.sygnif/sygnif-py-tools.py`), define `register(reg)`, and
drop entries into the registry.

## Layout

```
seat.py            agent loop + REPL + OpenAI-compatible transport
tools.py           built-in tools + plugin loader
models.py          model/preset registry (config.json + ~/.sygnif/sygnif-py.json)
identity.py        system prompt + tool protocol + live tool catalog
config.json        the shipped registry (fable/Fable 5.1 default + claude + openrouter-free + inkling + presets + BYO examples)
centre.py          the Centre — neuron registry + HTTP endpoint (the knot point)
commander.py       the commander — sandboxed fs/exec JSON-RPC server (the hands)
sygnif.sh/.ps1             seat launchers (Linux/macOS · Windows)
sygnif-centre.sh/.ps1      Centre launchers
sygnif-commander.sh/.ps1   commander launchers (mint a bearer token)
install.sh    curl|sh installer          install.ps1  irm|iex installer
```

## Safety

The seat has real hands on your machine (`shell`, `write_file`, `dev_apply_and_test`).
Run `--confirm` (or set `SYGNIF_PY_CONFIRM=1`) to approve each such call. The `chat`
preset has no system access at all. The **commander** is default-deny (path +
command allowlists) and fails closed without a token; the **Centre** is loopback-only
unless you give it a token.
