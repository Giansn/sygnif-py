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

## webapp — role mode: testing your own web application
For a developer testing pages you own or are authorized to test.
- Fingerprint first: `whatweb <url>`, `wafw00f <url>`. Know the stack and what
  filters you before you make noise.
- Content discovery for things that should never be public: `ffuf`/`feroxbuster`
  against a wordlist for `.git/`, `.env`, `.DS_Store`, `*.bak`/`*.sql`/`*.zip`
  backups, `/admin`, `/phpinfo.php`, `/.well-known`, source maps (`.js.map`).
  A live `.git/` or `.env` is a critical finding — record it with the exact URL
  and the leaked content as evidence.
- Vulnerability sweep, low-noise: `nuclei -u <url>` (CVEs, misconfig, exposures),
  `nikto -h <url>`. Corroborate before asserting.
- Injection on YOUR OWN parameters only: `sqlmap -u '<url?param=1>' --batch` for
  SQLi; test reflected/stored XSS by hand; check SSRF/SSTI/IDOR on endpoints you
  control. Never point these at third-party sites.
- Response hygiene (cheap wins devs usually miss): security headers
  (`curl -sI <url>` -> CSP, Strict-Transport-Security, X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy, Permissions-Policy), cookie flags
  (HttpOnly, Secure, SameSite), CORS (`Access-Control-Allow-Origin: *` with
  credentials is a finding), and CSRF protection on state-changing forms.
- Each issue becomes a `finding` only with a reproducible request/response pair.

## wpsec — role mode: WordPress security review
For your own WordPress site. WPScan's vuln data needs a free API token
(https://wpscan.com/api) — pass it with `--api-token <TOK>`; without it you get
enumeration but no CVE matches.
- Enumerate: `wpscan --url <url> --enumerate vp,vt,u,cb,dbe --api-token <TOK>`
  — vulnerable plugins (vp), vulnerable themes (vt), users (u), config backups
  (cb), db exports (dbe). Version + outdated plugins/themes are the usual way in.
- User enumeration also via the REST API: `/wp-json/wp/v2/users` and
  `/?rest_route=/wp/v2/users`. If it lists usernames, that feeds brute force.
- `xmlrpc.php`: check it's reachable (`curl -s <url>/xmlrpc.php`); `system.multicall`
  enables login brute-force amplification and pingback SSRF/DDoS. Disable if unused.
- Exposure checks: `wp-config.php`/`wp-config.php.bak`/`.swp`, `/wp-content/uploads/`
  directory listing, `readme.html` (version disclosure), `/wp-content/debug.log`,
  exposed `/wp-admin/install.php`.
- CVE sweep with `nuclei -u <url> -tags wordpress`.
- Built-in shortcut: the **`wp_vulnscan`** tool detects core/plugins/themes + versions
  and flags out-of-date ones; **`vuln_check`** looks up CVEs for a component+version or a
  CVE id. Set `WPSCAN_API_TOKEN` (free at wpscan.com/api) for exact affected-version
  ranges; otherwise they use keyless NVD (best-effort) + the WordPress.org latest-version
  signal. Passive detection can be masked — confirm with `wpscan` for depth.
- Watch the components your builds actually use: **Elementor** (+ its add-ons) and the
  **LiteSpeed Cache** plugin have both had critical CVEs; keep them current and version-check
  every site on each maintenance pass.
- Hardening to verify (report as findings if missing): login throttling / lockout,
  2FA on admin, `DISALLOW_FILE_EDIT` set, admin only over TLS, latest core +
  plugins, least-privilege DB user, file permissions (`wp-config.php` not world-
  readable), and a WAF/security plugin.

## hosting — role mode: hosting and infrastructure review
For the server/hosting behind your own sites.
- Exposed surface: `nmap -sV -sC <host>` — confirm ONLY what should be public is
  (80/443 yes; SSH/DB/panels usually should be firewalled or IP-restricted).
- TLS: `testssl.sh <host>` or `sslscan <host>` — protocol versions (no SSLv3/TLS1.0),
  weak ciphers, cert validity/chain, HSTS. A weak/expired cert is a finding.
- Mail spoofing (often wide open on small hosts): check DNS `SPF`, `DKIM`, `DMARC`
  (`dig TXT <domain>`, `dig TXT _dmarc.<domain>`). Missing DMARC = anyone can
  spoof your domain — record it.
- Subdomains + takeover: `subfinder -d <domain>` / `amass enum -d <domain>`, then
  check any CNAME pointing at an unclaimed service (GitHub Pages, S3, Heroku...)
  — a dangling CNAME is a subdomain-takeover finding.
- Panels & defaults: look for phpMyAdmin, cPanel/Plesk, Adminer, `.git` on the
  webroot, directory listing, and default/weak credentials on anything found.
- Backups & secrets in the webroot: `.sql` dumps, `.env`, archive files served
  over HTTP. These are critical if present.

## redteam — role mode: full authorized engagement (structured offensive tools)
Only ever inside a signed authorization; record scope in `~/sygnif-pentest/SCOPE.md` first.
The seat ships structured, auth-gated wrappers around the standard full-power tools —
each REFUSES without a `target` and an `authorization` attestation, and is confined to
SCOPE.md when it lists targets:
- `recon` — subfinder + DNS/SPF/DMARC + whatweb + httpx (recon/OSINT).
- `nuclei` — templated CVE/misconfig scan (add the Wordfence WP-CVE templates via
  `SYGNIF_PY_NUCLEI_EXTRA_TEMPLATES`).
- `wpscan` — full WordPress enumeration (`WPSCAN_API_TOKEN` for CVE data).
- `wp_vulnscan` / `vuln_check` — passive WP component detection / NVD+WPScan CVE lookup.
- `exploit_search` — offline Exploit-DB (searchsploit).
- `msf` — run a Metasploit module non-interactively (validate blast radius; least-destructive first).
- `bruteforce` — hydra online credential testing (loud, can lock accounts; rate-agreed only).
- `crack` — offline hash cracking (hashcat/john) on hashes you are authorized to hold.
- `postexploit` — LOCAL privesc enumeration only (linpeas); no persistence/lateral movement.
- `wifi_capture` / `wifi_crack` — WPA handshake/PMKID capture (hcxdumptool) + offline crack,
  on a network you are authorized to test, monitor-mode interface required.
Discipline: no mass targeting, no persistence, no evasion. Every finding = reproducible
evidence. Re-check scope before exploit/post-ex/wifi steps.
