"""Model + preset registry for SYGNIF py (the generic seat).

Unlike a single-proxy seat, every model here is self-describing: it carries its
own OpenAI-compatible `base_url`, an optional `api_key_env` (the NAME of an env
var holding the key — never the key itself), and its context/max_tokens. That is
what makes the seat model-agnostic: bring any OpenAI-compatible endpoint.

Config lives in config.json next to this module and may be overridden per-user by
~/.sygnif/sygnif-py.json (same shape). The two are merged: `models` and `presets`
are dict-updated (user file wins per key), `default_preset` is replaced if set.

Config shape:
  {
    "models": {
      "<key>": { "id": "<model id sent as `model`>",
                 "base_url": "https://.../v1",
                 "api_key_env": "OPENAI_API_KEY" | null,
                 "context": 128000, "max_tokens": 4096 },
      ...
    },
    "default_preset": "<preset name>",
    "presets": {
      "<name>": { "model": "<models key>", "tools": [...], "focus": "..." },
      ...
    }
  }
"""
from __future__ import annotations

import json
import os

SEAT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("SYGNIF_PY_CONFIG", os.path.join(SEAT_DIR, "config.json"))
USER_CONFIG = os.path.expanduser(
    os.environ.get("SYGNIF_PY_USER_CONFIG", "~/.sygnif/sygnif-py.json")
)

DEFAULT_TOOLS = ["shell", "read_file", "write_file", "note", "identity"]

# Keys starting with "_" in the config are documentation/examples, not real
# entries — skipped when building the live registry.
def _is_meta(key: str) -> bool:
    return key.startswith("_")


# Used only if config.json is missing/broken AND no preset resolves — the seat
# must still start rather than crash. Points at the shipped free OpenRouter slug.
_FALLBACK_MODEL = {
    "id": os.environ.get("SYGNIF_PY_MODEL", "nvidia/nemotron-3.5-lightning:free"),
    "base_url": os.environ.get("SYGNIF_PY_BASE_URL", "https://openrouter.ai/api/v1"),
    "api_key_env": os.environ.get("SYGNIF_PY_API_KEY_ENV", "OPENROUTER_API_KEY") or None,
    "context": 1000000,
    "max_tokens": 4096,
}
_FALLBACK_PRESET = {
    "model": "openrouter-free",
    "tools": DEFAULT_TOOLS,
    "focus": "General-purpose assistant. Understand the task, then use the tools to act, grounding claims in real output.",
}


def _read_json(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except Exception as e:  # noqa: BLE001
        print(f"[sygnif-py] config {path} failed to load: {e}")
        return None


def load_config() -> dict:
    """Return the merged config (config.json overlaid by the per-user file)."""
    cfg = _read_json(CONFIG_PATH) or {}
    cfg.setdefault("models", {})
    cfg.setdefault("presets", {})
    cfg.setdefault("default_preset", "assistant")

    user = _read_json(USER_CONFIG)
    if isinstance(user, dict):
        if isinstance(user.get("models"), dict):
            cfg["models"].update(user["models"])
        if isinstance(user.get("presets"), dict):
            cfg["presets"].update(user["presets"])
        if user.get("default_preset"):
            cfg["default_preset"] = user["default_preset"]
        # Anything else the config carries (e.g. the "nexus" block of portal types)
        # overlays too, one level deep: a per-user file that declares a new portal
        # type should not have to restate the shipped ones. Without this, keys
        # other than the three above were silently dropped from the user file.
        for key, val in user.items():
            if key in ("models", "presets", "default_preset"):
                continue
            if isinstance(val, dict) and isinstance(cfg.get(key), dict):
                merged = dict(cfg[key])
                for k, v in val.items():
                    if isinstance(v, dict) and isinstance(merged.get(k), dict):
                        merged[k] = {**merged[k], **v}
                    else:
                        merged[k] = v
                cfg[key] = merged
            else:
                cfg[key] = val
    return cfg


def list_models(cfg: dict) -> list[str]:
    return sorted(k for k in cfg.get("models", {}) if not _is_meta(k))


def resolve_model(cfg: dict, name: str, strict: bool = True) -> dict:
    """Return a model spec dict {id, base_url, api_key, context, max_tokens}.

    `name` is a key in the models table. With strict=True (default), a name that
    is given but not configured raises ValueError — the model the user chose must
    be the model that answers, so an unknown name is never silently swapped for a
    different one. A falsy name (no choice made), or an empty models table
    (unconfigured), yields the shipped fallback. The named api_key_env is read
    from the environment here (the file only stores the var name).
    """
    models = cfg.get("models", {})
    spec = None
    if name and name in models and not _is_meta(name):
        spec = dict(models[name])
    elif name and models and strict:
        # A model was explicitly named but is not configured. NEVER silently
        # substitute a different model — the model the user chose must be the model
        # that answers. The caller catches this and refuses the switch (or exits at
        # startup), keeping whatever model was already active.
        raise ValueError(
            "unknown model '" + str(name) + "'. Configured models: "
            + ", ".join(m for m in models if not _is_meta(m)))
    if spec is None:
        spec = dict(_FALLBACK_MODEL)
    key_env = spec.get("api_key_env")
    spec["api_key"] = os.environ.get(key_env) if key_env else None
    spec.setdefault("id", _FALLBACK_MODEL["id"])
    spec.setdefault("base_url", _FALLBACK_MODEL["base_url"])
    spec.setdefault("context", 32768)
    spec.setdefault("max_tokens", 4096)
    return spec


def model_status(cfg: dict, name: str) -> tuple[str, str]:
    """(state, hint) for one model, so /models and doctor can show readiness
    instead of a bare name. States: ready | needs-login | needs-key | keyless.
    Never runs a network call — it only inspects local presence."""
    import shutil
    spec = resolve_model(cfg, name)
    if spec.get("provider") == "claude-cli":
        claude = os.environ.get("SYGNIF_PY_CLAUDE_BIN", "claude")
        if not shutil.which(claude):
            return "needs-login", "claude CLI not installed — see claude.com/claude-code"
        # Logged-in state is only knowable by trying; treat installed CLI as ready
        # and let a real turn surface a login prompt if the token is stale.
        return "ready", "Claude subscription via claude CLI"
    key_env = spec.get("api_key_env")
    if key_env:
        if os.environ.get(key_env):
            return "ready", "key present in $" + key_env
        return "needs-key", "set $" + key_env
    return "keyless", "local/keyless endpoint " + (spec.get("base_url") or "")


def get_preset(cfg: dict, name: str | None) -> tuple[str, dict]:
    """Resolve a preset by name, falling back to default_preset.

    Returns (resolved_name, preset_dict). The preset_dict keeps its "model" as a
    models-table key; callers pass that key to resolve_model.
    """
    presets = cfg.get("presets", {})
    chosen = name or cfg.get("default_preset")
    if chosen not in presets:
        chosen = cfg.get("default_preset")
    if chosen not in presets:
        return "assistant", dict(_FALLBACK_PRESET)
    preset = dict(presets[chosen])
    preset.setdefault("tools", DEFAULT_TOOLS)
    preset.setdefault("focus", "")
    preset.setdefault("model", cfg.get("default_preset"))
    return chosen, preset


def list_presets(cfg: dict) -> list[str]:
    return sorted(cfg.get("presets", {}))
