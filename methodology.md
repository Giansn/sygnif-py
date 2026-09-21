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
- `c2` — orchestrate a Sliver C2 (listener / generate beacon / sessions / exec) for authorized adversary emulation. Standard framework only; no custom implants or evasion. Live interactive control belongs in sliver-client.
Discipline: no mass targeting, no persistence, no evasion. Every finding = reproducible
evidence. Re-check scope before exploit/post-ex/wifi steps.

## runbook — how the tools connect (authorized engagements only)
This is the operator runbook: how to find vulnerabilities and capture handshakes,
and how each tool feeds the next. Everything here assumes a target you own or are
authorized to test, recorded in SCOPE.md. The structured seat tools (recon,
nuclei, wpscan, wp_vulnscan, vuln_check, msf, bruteforce, crack, postexploit,
wifi_capture, wifi_crack, c2) wrap these commands behind the authorization gate;
the raw commands below are what they run and what you'd run by hand.

The chain, end to end:
  recon (find hosts/domains) -> enum (map each service) -> vuln (find weaknesses)
  -> exploit (prove impact) -> loot/report. Wireless is its own chain:
  capture -> convert -> crack. Web is: fingerprint -> discover -> scan -> confirm.

Data flows by file: one tool's output is the next tool's input.
  subfinder -> httpx -> nuclei         (subdomains -> live hosts -> vuln scan)
  nmap -oA -> feed services to enum     (ports -> targeted enumeration)
  hcxdumptool -> hcxpcapngtool -> hashcat   (capture -> hash -> crack)
  wpscan/searchsploit -> msf            (version -> matching exploit module)

## chaining — worked pipelines
Web app, own site:
  subfinder -silent -d DOMAIN | httpx -silent -title -tech-detect > live.txt
  nuclei -l live.txt -severity critical,high -o findings.txt
  ffuf -u https://SITE/FUZZ -w wordlist -mc 200,301,403 -o content.json
  # anything interesting -> confirm by hand (Burp Repeater) -> record with `finding`
WordPress, own site:
  wp_vulnscan {url}                       # passive: components + outdated
  wpscan --url URL --enumerate vp,vt,u,cb,dbe --api-token TOK   # active + CVEs
  vuln_check {slug:"<plugin>", version:"<v>"}   # confirm a specific CVE
Network host:
  nmap -sV -sC -oA scan TARGET            # -oA writes scan.{nmap,gnmap,xml}
  searchsploit <service> <version>        # version -> public exploit
  # validate scope + blast radius, then msf or a manual PoC
Wireless, own AP: see the `handshake` section.

## nmap — port & service discovery
Install: apt install nmap. Core:
  nmap -sV -sC -p- -oA out TARGET    # all ports, version + default scripts, save all formats
  nmap -sV --top-ports 1000 TARGET   # faster, common ports
  nmap --script vuln TARGET          # NSE vuln scripts (noisy)
  nmap -sn 10.0.0.0/24               # host discovery only (ping sweep)
Flags: -sV service/version, -sC default scripts, -p- all 65535, -oA basename
(saves .nmap/.gnmap/.xml — the .xml feeds other tools), -T4 faster, -Pn skip host
discovery. Read the .nmap for the service map; that map drives enum.

## nuclei — templated vulnerability scanning (highest signal for web)
Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest, then
`nuclei -update-templates`. Core:
  nuclei -u https://TARGET                       # single URL
  nuclei -l live.txt                             # a list from httpx
  nuclei -u URL -tags wordpress,cve -severity critical,high
  nuclei -u URL -t /path/to/templates            # custom template dir
More (verified flags): -as automatic scan (wappalyzer tech -> template tags), -c 25
concurrency, -rl 150 rate-limit, -jsonl -o out.jsonl structured output, -nt run only
newly-added templates, -as for an unknown stack, -ai '<prompt>' to generate a template.
WordPress CVE coverage without a WPScan token: clone topscoder/nuclei-wordfence-cve
and point at it: nuclei -u URL -t /path/to/nuclei-wordfence-cve (or set
SYGNIF_PY_NUCLEI_EXTRA_TEMPLATES so the `nuclei` seat tool includes it). Templates
ARE effectively a runnable CVE database; keep them updated. Confirm every hit.

## wpscan — WordPress enumeration
Install: gem install wpscan (or apt). Free CVE data needs a token from wpscan.com/api.
  wpscan --url https://SITE --enumerate vp,vt,u,cb,dbe --api-token TOK --random-user-agent
vp=vulnerable plugins, vt=vulnerable themes, u=users, cb=config backups, dbe=db
exports. Add --plugins-detection aggressive to find hidden plugins (louder). User
enum feeds a password test; outdated plugin+CVE is the usual finding. Passive
alternative that needs no install: the `wp_vulnscan` seat tool.

## ffuf — content & parameter discovery
Install: go install github.com/ffuf/ffuf/v2@latest. Core:
  ffuf -u https://SITE/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,204,301,302,307,401,403
  ffuf -u https://SITE/FUZZ -w list -e .php,.bak,.zip,.sql -mc all -fc 404
  ffuf -u 'https://SITE/?FUZZ=1' -w params.txt -fs 0     # parameter discovery, filter by size
FUZZ is the injection point. -mc match codes, -fc filter codes, -fs filter size,
-recursion. Finds .git/.env/backups/admin panels -> a live one is a real finding.
Wordlists: the seclists package (/usr/share/seclists).

## sqlmap — SQL injection (your own parameters only)
Install: apt install sqlmap. Core:
  sqlmap -u 'https://SITE/page?id=1' --batch            # detect
  sqlmap -u '...' --batch --dbs                          # list databases
  sqlmap -u '...' -D dbname --tables                     # then --dump
  sqlmap -r request.txt --batch                          # from a saved Burp request
--batch = no prompts, --level 1-5 / --risk 1-3 raise depth (and noise), -p PARAM to
target one parameter, --technique BEUSTQ to pick techniques, --forms --crawl=2 to find
and test forms, --random-agent, --os-shell for a shell (very intrusive). --dump extracts;
--dump-format CSV/HTML. Only against parameters you are authorized to test.

## hydra — online credential testing (loud; can lock accounts)
Install: apt install hydra. Core:
  hydra -L users.txt -P passwords.txt ssh://TARGET
  hydra -l admin -P pass.txt TARGET http-post-form '/login:user=^USER^&pass=^PASS^:F=incorrect'
  hydra -L users -P pass TARGET -s 443 https-get /admin
-L userlist / -l single user, -P passlist / -p single pass, -t threads (keep low,
4), -f stop on first hit. The http-post-form spec is path:body:failure-string.
Authorized + rate-agreed only — this is noisy and locks accounts.

## hashcat — offline hash cracking (GPU)
Install: apt install hashcat. Core:
  hashcat -m MODE hashes.txt wordlist.txt              # dictionary
  hashcat -m MODE hashes.txt wordlist -r rules/best64.rule    # + rules
  hashcat -m MODE hashes.txt -a 3 '?d?d?d?d?d?d?d?d'   # mask/brute
Modes: 22000 = WPA-PBKDF2-PMKID+EAPOL (wifi), 0 = MD5, 100 = SHA1, 1000 = NTLM,
1800 = sha512crypt, 3200 = bcrypt. -a 0 dictionary, -a 3 mask. Wordlist:
/usr/share/wordlists/rockyou.txt. -r rules/best64.rule mutates words, -a 0 dictionary /
-a 3 mask, --username if the file is user:hash, --show prints cracked (from the potfile),
--left prints still-uncracked. `hashcat -m MODE --show hashes.txt` after a run.

## metasploit — exploitation framework
Install: apt install metasploit-framework. Non-interactive (what the `msf` tool does):
  msfconsole -q -x "use MODULE; set RHOSTS TARGET; set LHOST me; run; exit"
Discover: search TYPE PRODUCT; info MODULE; show options. Validate the module,
its blast radius, and that the target is in scope BEFORE run. Prefer auxiliary/
scanner and check actions first; least-destructive proof. msfvenom builds payloads
(authorized engagements only). Capture the exact module+options+output as evidence.

## handshake — WPA/WPA2/WPA3 capture and crack (your own network)
Only against a network you own or are explicitly authorized to test. Chain, per the
hcxdumptool README: hcxdumptool -> hcxpcapngtool -> hashcat. The capture tool and
the converter versions MUST match, and the Wi-Fi adapter must support monitor mode
AND frame injection (many built-in Intel/Broadcom chips do not; use a known-good
external adapter, e.g. an Atheros/Ralink/MediaTek that supports it).
1. hcxdumptool path (>= 6.3 / 7.x) — it sets monitor mode ITSELF, so pass the
   PHYSICAL interface (wlan0, not wlan0mon) and do NOT run airmon-ng first:
     sudo hcxdumptool -i wlan0 -w capture.pcapng -F         # -F = all frequencies
     sudo hcxdumptool -i wlan0 -w capture.pcapng -c 11a     # one channel (band letter: a=2.4,b=5,c=6GHz)
   Target ONE AP by compiling a BPF on its BSSID (the removed --filterlist_ap):
     hcxdumptool --bpfc="wlan addr3 112233445566" > t.bpf   # BSSID, no colons
     sudo hcxdumptool -i wlan0 -w capture.pcapng -F --bpf=t.bpf
   Optional: --exitoneapol=1 stops on the first EAPOL. Check `hcxdumptool -h` — flags
   DRIFT between versions (6.2 -> 6.3 -> 7.x removed/renamed several).
2. aircrack path (alternative; here you DO set monitor mode):
     sudo airmon-ng start wlan0            # -> wlan0mon
     sudo airodump-ng -c CHANNEL --bssid AA:BB:CC:DD:EE:FF -w cap wlan0mon
   PMKID needs no client; a 4-way handshake needs a client to (re)associate —
   aireplay-ng -0 1 -a BSSID wlan0mon (deauth) forces it, only on your own AP.
3. Convert to a hashcat-crackable hash (hcxtools):
     hcxpcapngtool -o hash.22000 capture.pcapng
4. Crack offline:
     hashcat -m 22000 hash.22000 /usr/share/wordlists/rockyou.txt
The seat tools wifi_capture (step 2) and wifi_crack (steps 3-4) wrap this behind
the authorization gate. WPA3-SAE resists this; it applies to WPA/WPA2 (and WPA2/3
transition mode).

## osint — passive intelligence before you touch anything
  theHarvester -d DOMAIN -b all                 # emails, hosts, names
  subfinder -silent -d DOMAIN                    # subdomains (passive)
  amass enum -passive -d DOMAIN                  # deeper passive subdomains
  dig TXT DOMAIN; dig TXT _dmarc.DOMAIN          # SPF/DKIM/DMARC (mail spoofing)
  curl -s 'https://crt.sh/?q=%25.DOMAIN&output=json'   # certificate transparency
  whatweb DOMAIN                                  # tech stack
Passive first means no packets to the target's own infra where possible — build the
asset map before active scanning. The `recon` seat tool runs the core of this.

## network — role mode: network security testing (authorized)
Map and enumerate a network you are authorized to test.
- `portscan` — nmap -sV -sC (service/version + default scripts); or raw nmap via kali.
- `netenum` — SMB (enum4linux-ng, smbmap, nxc --shares: null sessions, shares, users) or
  SNMP (onesixtyone + snmpwalk with community strings).
- `tls_check` — testssl/sslscan per exposed TLS service.
- Sniffing/analysis: tshark / tcpdump on an interface you own (passive).
- Lateral/AD: nxc (CrackMapExec) for spray/exec, BloodHound for attack paths — scope-gated.
Chain: portscan -> per service netenum -> vuln/exploit. Every finding = reproducible output.

## passwords — role mode: credential strength & testing
- `pw_strength` — test a password locally + HaveIBeenPwned (k-anonymity; the password never
  leaves the machine). Use it to prove weak/breached passwords in a policy review.
- Online testing: `bruteforce` (hydra) — loud, lockout risk, rate-agreed only.
- Offline: `crack` (hashcat -m <mode>, -r rules) on hashes you are authorized to hold.
- Build target wordlists with cewl; base lists in seclists (/usr/share/seclists).

## cellular — role mode: DEFENSIVE cellular / network link (authorized, own device)
Observation only. Transmitting on cellular bands or intercepting others' traffic is illegal
and NOT provided here.
- `cell_info mode=serving` — your OWN modem's serving cell (operator, RAT, signal, cell id)
  via ModemManager (mmcli). Useful for a van/field uplink health + coverage.
- `cell_info mode=lookup` — geolocate a tower by mcc/mnc/lac/cellid (OpenCellID, free key).
- `cell_info mode=detect` — IMSI-catcher / rogue-base-station DETECTION guidance (SnoopSnitch,
  Crocodile Hunter): watch for forced 2G downgrade, unknown strong CellID, cipher downgrade.

## shodan — internet-wide passive intelligence (instructions + guidelines)
Shodan tells you what a host EXPOSES from its own scans — no packets to the target.
Use the `shodan` tool; `host` works keyless (InternetDB), the rest need SHODAN_API_KEY
(account.shodan.io -> free tier, or a membership for `vuln:` and larger result sets).
- Single host:  shodan {op:host, target:"1.2.3.4"}  or a domain (auto-resolved).
  Keyless InternetDB returns ports, CVEs, hostnames, CPEs, tags — the fastest
  "what's open + known-vulnerable" snapshot for one IP.
- Search the internet (key):  shodan {op:search, query:"..."}. Filter syntax:
    port:443  product:nginx  org:"Example AG"  net:1.2.3.0/24  hostname:example.com
    country:CH  city:Bern  ssl.cert.subject.cn:example.com  http.title:"admin"
    http.status:200  os:windows  has_screenshot:true  tag:cloud  vuln:CVE-2024-...
  Combine with spaces (AND). `vuln:` needs a paid membership.
- Counts / recon breadth (key):  shodan {op:count, query:"org:\"Example AG\""} —
  totals + facets (how many by port/product/country) without pulling results.
- Subdomains (key):  shodan {op:dns, domain:"example.com"}.  myip / info for account.
Guidelines: it is passive, but only research hosts you are authorized to look at, and
NEVER auto-scan/exploit an IP just because it appeared in a search — that needs its
own authorization. Data is as fresh as Shodan's last crawl; confirm before acting.
Pivot: shodan host -> confirm live with `portscan`/`nuclei` (authorized) -> `finding`.
Keyless (no key, no payment) beyond host: shodan {op:cve, cve:"CVE-..."} and
shodan {op:cvesearch, product:"wordpress", kev:true} query Shodan's CVEDB — CVSS +
EPSS (exploit-likelihood) + CISA-KEV (known-exploited), sorted by EPSS. Great for
PRIORITISING findings (fix KEV/high-EPSS first). Free-tier reality: the useful
Shodan data is keyless (InternetDB host lookup + CVEDB). A free ACCOUNT key adds
only fuller host banners + DNS resolve; `search`/`count` need paid query credits,
so treat search as unavailable unless a key with credits is set.

## containers — image / IaC / dependency security (trivy)
Use `container_scan`. type=image scans a registry image (no local Docker needed —
trivy pulls the layers itself); type=fs/repo/config scans a path (your code, a
checkout, Terraform/K8s manifests). Reports CVEs + leaked secrets + misconfig.
  container_scan {target:"nginx:1.25", type:"image"}
  container_scan {target:"~/mysite", type:"repo"}     # deps + secrets + Dockerfile
For a web dev: scan your image before you ship it, and your repo for a leaked .env
or a vulnerable dependency. Pair with `secrets_scan` (trufflehog/gitleaks) for depth.

## cloud — cloud security posture (prowler)
Use `cloud_audit {provider: aws|gcp|azure|kubernetes}` — hundreds of CIS-style checks
for misconfig (public buckets, over-broad IAM, unencrypted stores, open security
groups). Credentials come from the ENVIRONMENT, never stored by the seat:
  AWS  -> ~/.aws/credentials or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (+ AWS_PROFILE)
  GCP  -> Application Default Credentials (gcloud auth application-default login)
  Azure-> az login
Read-only posture review; run only on accounts you own or are authorized to audit.
First run auto-installs prowler into the toolbox (or `sygnif kali-setup`).

## crypto — encode / decode / hash / identify (instructions)
Use `crypto {op:..., data:...}`. Local + deterministic:
  encode/decode algo=base64|hex|url|rot13      hash algo=md5|sha1|sha256|sha512
  hmac (key + algo)      jwt (decode header+payload, signature NOT verified)
  identify (name a hash type — hashid/name-that-hash)
  magic (auto-decode/decrypt an unknown blob — ciphey)
For cracking a hash once identified, use `crack` (hashcat -m <mode>). JWT decode is
inspection only; it does not check or forge signatures.

## website — quick site recon (instructions)
Use `website {url:...}`. Passive: robots.txt, sitemap.xml, /.well-known/security.txt,
DNS (A/MX/TXT), whois, tech fingerprint (whatweb), and a Wayback snapshot count.
A fast first look before the deeper `webapp`/`wpsec`/`hosting` playbook flows.
