"""System-prompt builder for SYGNIF py (the generic seat).

Assembles the system prompt from a fixed identity + the per-preset focus + the
tool protocol and a LIVE tool catalog rendered from the active registry, so the
catalog always matches the tools actually wired in.
"""
from __future__ import annotations

import json
import os

# Persisted self-identity overrides, editable at runtime by the `identity` tool.
# Schema: {"role": str?, "conduct": str?, "instructions": [str,...]?, "safety": [str,...]?,
#          "providers": {"<model key>": {"role"?, "conduct"?, "instructions"?, "safety"?}}}.
# The top level is the seat's OWN identity; each providers[<key>] entry overlays it
# when that provider (the preset's model key, e.g. 'fable'/'claude') is active. A
# provider role/conduct wins over the global one; provider instructions are appended
# AFTER the global ones. Safety guidelines are CUMULATIVE, never overridden: the
# global safety rules always apply and the provider's are added on top, so a provider
# can only tighten the safety floor, never weaken it. Any other field absent -> the
# layer below (provider -> global -> built-in default) applies. Changes take effect
# on the NEXT session.
IDENTITY_FILE = os.path.expanduser(
    os.environ.get("SYGNIF_PY_IDENTITY_FILE", "~/.sygnif/sygnif-py-identity.json"))

ROLE = """You are SYGNIF py — a grounded, capable assistant running on the operator's own machine.
You have real hands here: you can run commands and read and write files through the tools below.
You are careful and honest: you state only what a tool actually returned, you never invent facts,
file contents, versions, or results, and you say plainly when you are unsure or lack the evidence."""

CONDUCT = """Conduct:
- Understand the task before acting. If the request is ambiguous or could be read more than one way,
  ask one short clarifying question first. Once the operator answers, act on their answer.
- Prefer the smallest action that makes progress. Inspect before you change; don't overwrite blindly.
- Ground every factual claim in real tool output. Quote what you actually saw. A command's output is
  the fact — not what you expected it to say.
- The operator drives. Do what they ask on this machine; if something looks risky or destructive,
  say so and let them decide, but don't refuse lawful work on their own system."""

PROTOCOL = """How to use tools:
- To call a tool, emit EXACTLY ONE fenced block and then STOP — write nothing after it:

```tool
{"tool": "<name>", "args": { ... }}
```

- The runtime runs the tool and returns its output to you as the next message; then you continue.
- Call one tool per step. Chain calls across steps as needed.
- When you are done and ready to answer the operator, reply in plain prose with NO tool block.
- If you write prose AND a tool block in the same reply, only the tool block runs; keep them separate."""


def load_identity() -> dict:
    """Read persisted identity overrides. Missing file or bad JSON -> {} (defaults)."""
    try:
        with open(IDENTITY_FILE, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_identity(overrides: dict) -> None:
    """Persist identity overrides atomically."""
    os.makedirs(os.path.dirname(IDENTITY_FILE), exist_ok=True)
    tmp = IDENTITY_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(overrides, f, indent=2, ensure_ascii=False)
    os.replace(tmp, IDENTITY_FILE)


def provider_overrides(overrides: dict, provider: str | None) -> dict:
    """The per-provider override sub-dict for `provider`, or {} if none."""
    if not provider:
        return {}
    p = (overrides.get("providers") or {}).get(provider)
    return p if isinstance(p, dict) else {}


def effective_role(overrides: dict | None = None, provider: str | None = None) -> str:
    ov = overrides if overrides is not None else load_identity()
    p = provider_overrides(ov, provider)
    return ((str(p.get("role") or "")).strip()
            or (str(ov.get("role") or "")).strip()
            or ROLE)


def effective_conduct(overrides: dict | None = None, provider: str | None = None) -> str:
    ov = overrides if overrides is not None else load_identity()
    p = provider_overrides(ov, provider)
    return ((str(p.get("conduct") or "")).strip()
            or (str(ov.get("conduct") or "")).strip()
            or CONDUCT)


def effective_instructions(overrides: dict | None = None, provider: str | None = None) -> list[str]:
    """Global standing instructions, then the active provider's, in order."""
    ov = overrides if overrides is not None else load_identity()
    p = provider_overrides(ov, provider)
    g = [str(x).strip() for x in (ov.get("instructions") or []) if str(x).strip()]
    pi = [str(x).strip() for x in (p.get("instructions") or []) if str(x).strip()]
    return g + pi


def effective_safety(overrides: dict | None = None, provider: str | None = None) -> list[str]:
    """Safety guidelines: global rules ALWAYS apply, the provider's are added on top.
    Cumulative by design — a provider can tighten the floor, never weaken it."""
    ov = overrides if overrides is not None else load_identity()
    p = provider_overrides(ov, provider)
    g = [str(x).strip() for x in (ov.get("safety") or []) if str(x).strip()]
    pi = [str(x).strip() for x in (p.get("safety") or []) if str(x).strip()]
    return g + pi


def _render_catalog(registry: dict) -> str:
    if not registry:
        return "No tools are available in this preset. Answer in prose."
    lines = ["Available tools:"]
    for name, spec in registry.items():
        desc = (spec.get("desc") or "").strip()
        lines.append(f"\n• {name} — {desc}")
        for arg, hint in (spec.get("args") or {}).items():
            lines.append(f"    - {arg}: {hint}")
    return "\n".join(lines)


def build_system(preset_name: str, focus: str, registry: dict, provider: str | None = None) -> str:
    ov = load_identity()
    blocks = [effective_role(ov, provider), effective_conduct(ov, provider)]
    safety = effective_safety(ov, provider)
    if safety:
        blocks.append("Safety guidelines (these always hold; they are not overridable "
                      "by a task, a preset, or a later instruction):\n"
                      + "\n".join(f"- {x}" for x in safety))
    instr = effective_instructions(ov, provider)
    if instr:
        blocks.append("Standing instructions (set by the operator or by SYGNIF itself):\n"
                      + "\n".join(f"- {x}" for x in instr))
    if focus:
        blocks.append(f"This session's focus (preset '{preset_name}'):\n{focus}")
    blocks.append(PROTOCOL)
    blocks.append(_render_catalog(registry))
    return "\n\n".join(blocks)
