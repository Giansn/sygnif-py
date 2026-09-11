# SYGNIF py

A tiny, dependency-free **SYGNIF seat** in Python — the generic cousin of SYGNIF pi.
It's an agent loop over **any OpenAI-compatible chat endpoint**: the model calls
tools by emitting a fenced `` ```tool `` block, the seat runs the tool on your
machine and feeds the result back, and it loops until the model answers.

No private models are baked in. Out of the box it points at a **free public
OpenRouter model** so it works after one `export`; you can also log in to your own
**Claude Pro/Max subscription** with `sygnif login`, or add any other endpoint.

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

## First run — pick how it talks to a model

The default model is a **free** OpenRouter slug, so the fastest start is:

```sh
# 1. make a free key at https://openrouter.ai/keys  (no card needed)
export OPENROUTER_API_KEY=sk-or-...
sygnif "hello"
```

Prefer your own **Claude subscription** (billed to Pro/Max, not pay-per-use API)?
Install the [claude CLI](https://claude.com/claude-code), then:

```sh
sygnif login                 # wraps `claude setup-token` (one time)
sygnif --model claude "hello"
```

Free OpenRouter slugs rotate; if the default 404s, pick a current one from
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

## Models — bring your own

Three models ship listed:

| model | what it is | to use |
|---|---|---|
| `openrouter-free` *(default)* | a free public OpenRouter slug — the out-of-box default | `export OPENROUTER_API_KEY=...` |
| `claude` | your own Claude Pro/Max subscription via the official `claude` CLI | `sygnif login` (needs the claude CLI) |
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
config.json        the shipped registry (openrouter-free default + claude + inkling + presets + BYO examples)
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
