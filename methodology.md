# SYGNIF pentest methodology

A compact, offline kill-chain checklist for an authorized engagement. Read a
section with the `playbook` tool (e.g. `playbook section=recon`). Track where you
are with `phase`; record what you prove with `finding`; produce the deliverable
with `report`. Only ever act inside the authorization recorded in SCOPE.md.

## recon — passive and active discovery
- Confirm scope against SCOPE.md before touching anything. Out-of-scope = stop.
- Passive first: whois, DNS (dnsrecon, dnsenum, amass, subfinder), certificate
  transparency, theHarvester for emails/hosts, whatweb for stacks.
- Active surface: nmap host discovery then service/version scan
  (`nmap -sV -sC -p- <target>`), masscan for wide ranges.
- Goal: an asset map — live hosts, open ports, service versions. Record notable
  exposure as findings only when the scan output proves it.

## enum — enumerate each exposed service
- Web: whatweb, then directory/content discovery (gobuster, feroxbuster, ffuf),
  wafw00f to know what filters you. Map every endpoint before testing it.
- SMB/AD: enum4linux-ng, smbmap, smbclient; null sessions, shares, users.
- Other: sslscan/sslyze for TLS, snmp, dns zone transfer attempts.
- Goal: a concrete list of testable entry points per service.

## vuln — analysis, low-noise first
- nuclei with appropriate templates; nikto for web; version-to-CVE via
  searchsploit. Confirm, do not trust a scanner's word.
- Manual checks for the OWASP top classes: injection (SQLi via sqlmap only on
  authorized params), XSS, SSRF, SSTI, IDOR, auth/session flaws, access control.
- Every candidate becomes a finding ONLY with reproducible evidence.

## exploit — prove impact, within scope
- Validate before you fire: understand the exploit, the blast radius, and that
  the target is in scope. Prefer the least-destructive proof of the issue.
- Tools: metasploit/msfconsole where apt, sqlmap for DB access, hydra/medusa for
  authorized credential testing, evil-winrm/impacket for Windows/AD.
- Capture the exact command and output as evidence for the finding.

## postexploit — only if the rules of engagement allow it
- Scope check again: lateral movement, persistence and data access are often
  explicitly out of scope. If unsure, ask the operator before proceeding.
- Pivoting: proxychains4, chisel. Loot handling per the agreed rules.

## report — the deliverable
- Run `report` to render findings.jsonl into report.md, grouped by severity.
- Each finding must carry: target, evidence, impact, and a fix recommendation.
- Re-read for accuracy: never ship a finding you cannot reproduce from evidence.

## scout — role mode: reconnaissance
Adopt when mapping the target. Breadth over depth: enumerate everything, assert
nothing, hand a clean asset/endpoint map to the analyzer. Stay passive until
active scanning is authorized.

## analyzer — role mode: vulnerability analysis
Adopt when triaging the scout's map. Turn surface into ranked hypotheses:
which endpoints/services are most likely vulnerable and why. Prioritise by
impact and likelihood; discard scanner noise that you cannot corroborate.

## exploiter — role mode: validation
Adopt when proving a hypothesis. One issue at a time, least-destructive proof,
in-scope only. Produce reproducible evidence — command plus output — for each
confirmed issue, then record it with `finding`.

## reporter — role mode: synthesis
Adopt at the end. Read every finding, check each is backed by evidence, dedupe,
order by severity, and run `report`. Write for the asset owner: what, where,
impact, and the concrete fix.
