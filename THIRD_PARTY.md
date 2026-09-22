# Third-party tools invoked by SYGNIF py

SYGNIF py is a wrapper: its tools shell out to external programs it does not bundle.
Those programs keep their own licenses; SYGNIF py neither copies nor redistributes their
source. `sygnif kali-setup` fetches them into the toolbox at install time.

## AGPL-3.0 — kept separate on purpose
- **EONRaider/Arp-Spoofer** (https://github.com/EONRaider/Arp-Spoofer) — the `arp` tool
  shells out to a copy cloned to `/opt/arp-spoofer` at setup. AGPL-3.0. It is a runtime
  dependency, invoked as a subprocess; its code is NOT vendored into this repository, so
  AGPL's copyleft does not extend to SYGNIF py's own source.

## Other tools (invoked, not bundled)
NetExec, Impacket, Certipy, bloodyAD, Coercer, evil-winrm, Pacu, ROADtools, AzureHound,
kube-hunter, Atomic Red Team, Velociraptor, Zeek, Suricata, Volatility3, Falco, LOKI,
YARA-Forge, chainsaw, nmap, nuclei, wpscan, sqlmap, hydra, hashcat, ZAP, Sliver, and the
rest of the Kali toolset — each under its own license, installed by kali-setup.
