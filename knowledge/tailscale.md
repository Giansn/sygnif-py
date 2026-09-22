# Tailscale — professional setup expertise

Bundled expertise so the seat can set a user or a small org up on Tailscale
properly, not just "install and log in." Tailscale is a WireGuard mesh VPN: every
device gets a stable 100.x address, talks peer-to-peer over encrypted tunnels, and a
coordination server exchanges only keys (never traffic). Access is by identity, not
network location.

## Setup runbook (do it in this order)

1. **Create the tailnet.** Sign up at tailscale.com with an identity provider (Google,
   Microsoft, GitHub, Okta, or email). For an org, use the SSO the company already runs
   so accounts follow the existing identity lifecycle. Each account gets a
   `<name>.ts.net` tailnet domain.
2. **Install the client** (each device):
   - Linux: `curl -fsSL https://tailscale.com/install.sh | sh`
   - macOS/Windows: the app store / installer; iOS/Android: the app.
   - Headless server: install, then `sudo tailscale up`.
3. **Join the device.** `sudo tailscale up` opens a browser auth, or use a
   pre-authorized key for unattended installs (below). Confirm with
   `tailscale status` and `tailscale ip -4`.
4. **Turn on MagicDNS** (admin console → DNS). Devices become reachable by name
   (`host.<tailnet>.ts.net`); always use names, not the 100.x addresses.
5. **Lock down access before you add services** — set the policy (grants) so the
   default isn't "everyone reaches everything." See hardening below.
6. **Verify a real path**: `tailscale ping <host>` (says direct vs DERP relay),
   `tailscale netcheck` (NAT type, nearest relay).

## Auth keys — unattended and CI installs

`tailscale up --authkey <KEY>` joins without a browser. Mint keys in the admin console:
- **Ephemeral** keys — the node auto-removes when it goes offline. Use for CI,
  containers, short-lived VMs.
- **Pre-approved / tagged** keys — attach ACL tags at join so the node lands with the
  right permissions and (if device approval is on) skips manual approval.
- **Reusable vs one-time** — one-time for a single host; reusable for a fleet rollout.
Never bake a long-lived reusable key into an image without tailnet lock + tight tags.

## Hardening from day one

- **Grants (the policy file).** New tailnets default to grants syntax (superset of the
  old ACLs, plus app-layer permissions). Start default-deny and grant narrowly. Key on
  **tags** (`tag:server`, `tag:ci`, `tag:prod`) not individual users, so access follows
  role. Use `via` to force traffic through a chosen exit node / subnet router.
- **Tailnet lock.** Require new nodes to be cryptographically signed by existing trusted
  devices before they can join — closes the "compromised coordination server adds a
  rogue node" risk. Turn it on for any security-sensitive tailnet.
- **Key expiry.** Leave device-key expiry on (default ~180 days) so stale devices drop
  out; only disable it deliberately for always-on infrastructure, and tag those.
- **Device approval** (org): require an admin to approve each new device.
- **SSO + SCIM/user groups** (org): manage membership from the IdP; users deprovisioned
  in the IdP lose tailnet access automatically.

## Features and when to use them

- **`tailscale serve`** — expose a local service to the **tailnet only**, with an
  automatic HTTPS cert. This is the default for internal apps.
  `tailscale serve --bg 8080` ; `tailscale serve status` ; `tailscale serve reset`.
- **`tailscale funnel`** — expose a *served* endpoint to the **public internet** at the
  `.ts.net` URL. Deliberate public exposure; only ports 443/8443/10000. Treat anything
  behind Funnel as internet-facing attack surface. `tailscale funnel 443 on`.
- **Exit node** — route a device's *outbound* internet through a peer:
  advertise with `tailscale up --advertise-exit-node`, use with
  `tailscale up --exit-node=<name>`; clear with `tailscale set --exit-node=`.
- **Subnet router** — reach a non-Tailscale LAN behind one node:
  `tailscale up --advertise-routes=10.0.0.0/24`, then approve the route in the admin
  console. The way to bring legacy/IoT/printers onto the tailnet without agents.
- **Tailscale SSH** — `tailscale up --ssh` gives keyless SSH between tailnet devices,
  authorized by the policy file (no key distribution). Scope it in grants; don't open it
  to the whole tailnet.
- **Taildrop** — `tailscale file cp <f> <host>:` for encrypted file transfer.
- **MagicDNS + split DNS** — resolve tailnet names automatically; add split-DNS to send
  a corporate domain's queries to an internal resolver reachable over the tailnet.

## Core CLI

```sh
tailscale up [--ssh] [--authkey K] [--advertise-exit-node] [--advertise-routes=CIDR]
tailscale status [--json]      tailscale ip -4        tailscale netcheck
tailscale ping <host>          tailscale set --exit-node=<name|->
tailscale serve --bg <port>    tailscale funnel <port> on
tailscale cert <name>.ts.net   tailscale lock status   tailscale file cp <f> <host>:
```

## Troubleshooting (fast)

| symptom | check | cause |
|---|---|---|
| node online but no TCP reaches it | `ip route show table 52` (Linux) | Tailscale routes got wiped (e.g. after a NetworkManager bounce) — restart `tailscaled` / `tailscale down && up` to reinstall them. Looks like a firewall block, is a missing route. |
| slow / high latency | `tailscale status` shows `relay` | no direct path (NAT); `tailscale netcheck`, allow UDP **41641** |
| MagicDNS name won't resolve | `/etc/resolv.conf`, admin DNS page | MagicDNS off, or resolv.conf clobbered by the OS network manager |
| new node can't join | `tailscale lock status` | tailnet lock — sign the node from a trusted device |
| Funnel URL 502 | `tailscale serve status` | the local port behind serve is down |
| HTTPS cert error | `tailscale cert <name>` ; clock | cert not provisioned, or time skew |

## Common mistakes to avoid

- Binding services to `0.0.0.0` "because it's on the VPN" — prefer `serve` (tailnet-only)
  so the service isn't also exposed on the local LAN/WAN.
- Leaving the policy at allow-all — set grants before adding sensitive services.
- Funnelling something you wouldn't put on a public IP.
- Long-lived reusable auth keys with no tailnet lock and broad tags.
- Using 100.x IPs in configs instead of MagicDNS names (IPs are stable, but names
  survive re-tagging and read clearly).

## Official docs

tailscale.com/kb · Funnel kb/1223 · Serve kb/1312 · Access control (grants) kb/1393 ·
Tailnet lock kb/1226 · Subnet routers kb/1019 · Exit nodes kb/1103 · SSH kb/1193.
