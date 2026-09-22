# SYGNIF py

A tiny, dependency-free **agent seat** in Python: a loop over any
OpenAI-compatible chat endpoint. The model calls tools by emitting a fenced
`` ```tool `` block, the seat runs the tool on your machine and feeds the result
back, and it loops until the model answers. Standard library only, Python 3.8+.

Default model is **Claude Fable 5.1** on your own Claude Pro/Max subscription (via
the official `claude` CLI). No login? Use a free OpenRouter model, or point it at
any endpoint that speaks `/v1/chat/completions` — OpenAI, Ollama, LM Studio,
`llama.cpp --server`.

## Install

```sh
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/Giansn/sygnif-py/main/dist/install.sh | sh
# Windows (PowerShell)
irm https://raw.githubusercontent.com/Giansn/sygnif-py/main/dist/install.ps1 | iex
```

## First run — just type `sygnif`

The first launch is guided (one-time, gated by `~/.sygnif/.sygnif-py-initialized`):
it offers to install prerequisites it can't bundle (`claude` CLI, `tmux`), runs
`claude setup-token` so Fable bills to your plan, creates `~/sygnif-pentest/` with
a `SCOPE.md` authorization reminder, reports which pentest tools are present and
offers to install the missing ones, then drops you into the **pentest** preset.
Turn the pieces off with `SYGNIF_PY_BOOTSTRAP=0`, `SYGNIF_PY_INSTALL_TOOLS=0`,
`SYGNIF_PY_FIRSTRUN=0`.

```sh
sygnif                       # REPL, default preset
sygnif --preset chat|dev|ops # chat-only · build→prove · host state via Centre
sygnif "list my home dir"    # one-shot
sygnif --confirm             # approve each shell / write / offensive call
/model openrouter-free       # then: export OPENROUTER_API_KEY=sk-or-...
```

REPL: `/preset` `/model` `/models` `/tools` `/reset` `/help` `/quit`. Over a TTY
it renders the **pix UI** (streamed reply, per-turn rule, a status line with model
/ context / throughput, clean `→ tool(args)` lines). `SYGNIF_PY_PIX=0` for plain.

## The three pieces

Each is self-contained and usable alone.

- **Seat (`sygnif`)** — the agent loop you run day to day.
- **Centre (`sygnif-centre`, `:9100`)** — one HTTP endpoint fronting **neurons**:
  `sys.state`, `sys.procs`, `note.*`, `knowledge.*`, and (for pentest)
  `pentest.hosts`. Extend it with `~/.sygnif/centre-neurons.py` defining
  `register(NEURONS)`. Loopback unless given `SYGNIF_PY_CENTRE_TOKEN`.
- **Commander (`sygnif-commander`, `:9110`)** — sandboxed, allowlisted fs/exec
  over JSON-RPC. Default-deny on both path and command; fails closed without a
  bearer token (minted on first run into `~/.sygnif/sygnif-py-commander.env`).

## Models — bring your own, and it stays chosen

| model | what | to use |
|---|---|---|
| `fable` *(default)* | Claude Fable 5.1 on your Pro/Max plan via the `claude` CLI | first run, or `sygnif login` |
| `claude` | any other model on your subscription | `sygnif login` |
| `openrouter-free` | a free public OpenRouter slug | `/model openrouter-free` + key |
| `inkling` | ThinkingMachines Inkling 256k on a local bridge | run the bridge |

Each model carries its own `base_url` and `api_key_env`, so **choosing a model
chooses its provider**. Model selection is strict: the model you pick is the model
that answers. A misspelled or unconfigured name is **refused**, never silently
swapped for another; `/model <bad>` keeps your current model, a bad `--model`
exits. There is **no automatic model or provider switching** at runtime.

Add your own in `~/.sygnif/sygnif-py.json` (merged over the shipped config, so
upgrades don't clobber it). API keys live in env vars named by `api_key_env`,
never in the file. Switch live with `/model <key>`, list with `/models`.

## Pentest — authorized engagements only

Structured, **auth-gated** wrappers around the standard tools: `recon`, `nuclei`,
`wpscan`, `msf`, `exploit_search`, `bruteforce`, `crack`, `postexploit`,
`privesc`, `portscan`, `netenum`, `dast`, `wifi_capture`/`wifi_crack`, `c2`
(standard framework, adversary emulation). Every offensive tool refuses without a
`target` and an `authorization` attestation. No mass targeting, no persistence,
no evasion.

**Guard rails (default-on):**

- **Scope** — when `~/sygnif-pentest/SCOPE.md` lists targets, a run must match an
  exact host, a subdomain of one, or an **IP inside a listed CIDR**.
- **Blast radius** — a `SCOPE.md`-adjacent `STOP` file is a kill-switch that halts
  every offensive tool; wildcards and over-broad CIDRs (> 256 hosts) are refused
  unless you pass `allow_range`; a rate limit caps runaway loops (40 calls / 60s).
- **`--confirm`** gates the offensive tools too, not just shell and file writes.
- **Findings** need real evidence; **high/critical** need a second, independent
  observation (`verify`) or they're refused — no single-source criticals.
- **Audit** — every offensive command appends to `audit.jsonl` (UTC, target,
  authorized-by, cmd, exit).
- **Inventory** — recon/portscan/netenum auto-fill `hosts.jsonl` (host/port/
  service); query it with the `inventory` tool or the `pentest.hosts` neuron.
- **Report** — `report` renders `report.md` + `report.html` (severity-graded),
  plus PDF if weasyprint/pandoc is present.

Authenticated web scans: pass `cookie`, `bearer`, or `headers` to `nuclei` /
`wpscan` to reach behind a login. `webdev` preset is the web-focused slice for
testing your **own** sites; `redteam` is the full engagement set. Install tools
with `sygnif kali-setup` (or a lighter `SYGNIF_PY_KALI_METAPACKAGE=kali-tools-web
sygnif kali-setup`), or run inside the `sygnif-kali` container. Read the concrete
checklists with `playbook section=<webapp|wpsec|hosting|redteam>`.

## Desk & Nexus

- **`sygnif-desk`** (`:8899`) — browser chat + saved workflows over your models.
  Generation continues server-side if you close the tab. Loopback only;
  `SYGNIF_DESK_EXEC=1` to allow shell from the Desk (off by default).
- **`nexus`** / **`sygnif-nexus`** (`:8910`) — labelled tmux **portals**
  (`<type>-<label>`) for running many agent sessions side by side, detachable and
  resumable. `nexus` (picker), `nexus <type> <label>` (attach-or-create),
  `nexus spawn|send|preview|rename|kill|resume`. Types are discovered (installed
  agent CLIs) or declared in config. Both front ends refuse to kill an attached
  portal without `-f`. Needs `tmux`.

Both bind loopback; tunnel with `ssh -N -L <port>:127.0.0.1:<port> <host>` rather
than exposing them.

## Tools & extension

Built-in: `shell`, `read_file`, `write_file`, `note`, `dev_apply_and_test`,
`centre`, `commander`, plus the pentest set above. A preset picks which are active.
Add your own without touching the core: copy `custom_tools.py.example` to
`custom_tools.py` (or `~/.sygnif/sygnif-py-tools.py`), define `register(reg)`.

## Layout

```
seat.py        agent loop + REPL + OpenAI-compatible transport
tools.py       built-in + pentest tools, scope/authz/blast guards, plugin loader
models.py      model/preset registry (strict resolution)
identity.py    system prompt + tool protocol + live catalog
centre.py      Centre: neuron registry + HTTP endpoint    centre_neurons.py  drop-in neurons
commander.py   sandboxed fs/exec JSON-RPC server
desk.py        browser chat/workflows      nexus.py  portal board
config.json    shipped models + presets    install.sh / install.ps1  installers
```

## Safety

The seat has real hands on your machine (`shell`, `write_file`,
`dev_apply_and_test`, and the offensive tools). Run `--confirm` (or
`SYGNIF_PY_CONFIRM=1`) to approve each. The `chat` preset has no system access.
Commander is default-deny and fails closed; Centre is loopback-only without a
token. Offensive tooling is for **authorized** testing — certified, written
authorization, scope confined to `SCOPE.md`, no mass or critical-infra targets.
