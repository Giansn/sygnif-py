"""SYGNIF py — Centre neuron plugin: the pentest asset inventory.

Drop-in loaded by centre.py (_load_plugins). Exposes hosts.jsonl — the asset base
that recon/portscan/netenum fill automatically (see tools._inventory_harvest, review
P1-5) — as a Centre neuron, so any host on the swarm can query the target base instead
of grepping notes. Read-only.

Neuron funcs return a plain {"ok": True, ...} / {"ok": False, "error": ...} dict, the
same shape centre._ok/_err produce (those helpers are not in this file's namespace).
"""
import os
import json

INVENTORY = os.path.expanduser(
    os.environ.get("SYGNIF_PY_INVENTORY",
                   os.path.join(os.environ.get("SYGNIF_PY_PENTEST_DIR", "~/sygnif-pentest"),
                                "hosts.jsonl")))


def _read():
    p = os.path.expanduser(INVENTORY)
    if not os.path.exists(p):
        return []
    rows = []
    for ln in open(p, encoding="utf-8"):
        try:
            rows.append(json.loads(ln))
        except Exception:
            pass
    return rows


def n_pentest_hosts(args: dict) -> dict:
    """Query the asset inventory. Filter by host / service / port substring."""
    rows = _read()
    fh = str(args.get("host", "")).strip().lower()
    fs = str(args.get("service", "")).strip().lower()
    fp = str(args.get("port", "")).strip()
    if fh:
        rows = [r for r in rows if fh in str(r.get("host", "")).lower()]
    if fs:
        rows = [r for r in rows if fs in str(r.get("service", "") or "").lower()]
    if fp:
        rows = [r for r in rows if str(r.get("port", "")) == fp]
    hosts = sorted({r.get("host") for r in rows if r.get("host")})
    return {"ok": True, "count": len(rows), "hosts": hosts, "rows": rows[:500]}


def register(NEURONS: dict) -> None:
    NEURONS["pentest.hosts"] = {
        "domain": "pentest",
        "description": ("Asset inventory (hosts + open ports/services) harvested from "
                        "recon/portscan/netenum. Filter by host, service, or port. The "
                        "queryable target base, not grep-over-notes."),
        "schema": {"host": "optional host filter", "service": "optional service filter",
                   "port": "optional port filter"},
        "func": n_pentest_hosts,
    }
