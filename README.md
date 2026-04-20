# IsItProxy

Domain routing analyser for pentest engagements.

Runs from your local machine and uses an SSH SOCKS tunnel to observe applications from the **jumpbox perspective**, then tells you exactly how traffic must be routed in tools like Burp Suite.

Built for environments where:

* You pivot through a jumpbox (VPN / SSH)
* The jumpbox has **no direct internet access**
* External access requires a **corporate proxy**
* Some traffic (e.g. Microsoft / Entra SSO, CDNs) must go **Direct Internet (DIA)**

---

## What problem this solves

Corporate routing is rarely simple:

```text
Internal App → Direct (VPN)
             → Proxy (corp proxy)
             → Direct Internet (DIA via PAC)
```

If you get routing wrong:

* Requests silently fail
* SSO breaks
* Burp becomes unreliable
* You waste time troubleshooting networking instead of testing

**IsItProxy identifies the correct path up front.**

---

## How it works

1. **SOCKS tunnel (jumpbox view)**
   Uses `ssh -D` to see the target from the jumpbox’s network perspective.

2. **Proxy testing (critical)**
   Determines if a domain is reachable:

   * directly (via SOCKS / VPN)
   * or only via **corporate proxy**

3. **PAC file parsing (optional but powerful)**
   Extracts:

   * `DIRECT` → DIA domains
   * `PROXY` → proxy-routed domains

4. **DNS analysis**

   * Local resolution (jumpbox view)
   * Public resolution (`8.8.8.8`)
   * Detects:

     * private/internal IPs
     * split-horizon DNS
     * anycast (not misclassified as internal)

5. **Deep crawling**
   Extracts domains from:

   * HTML (`href`, `src`, `action`, `data-*`)
   * JavaScript (inline + external: `fetch`, `axios`, XHR)
   * CSS (`url()`, `@import`)
   * headers (`CSP`, `Location`, `Link`)
   * redirect chains

6. **SSO / Identity chain discovery**
   Automatically surfaces authentication flows, commonly involving:

   * Microsoft / Microsoft Entra ID
     (`login.microsoftonline.com`, `aadcdn.*`, `msftauth.*`)
   * Other IdPs (Okta, Auth0, Ping, etc.)

   SSO often follows a **different routing path than the app itself**.

7. **Burp Suite config generation**
   Writes a ready-to-import config:

   * Internal → SOCKS
   * Proxy-only → handled via routing logic
   * DIA / External → direct from your machine

---

## Classification

| Label              | Colour     | Meaning                                                     |
| ------------------ | ---------- | ----------------------------------------------------------- |
| `INTERNAL`         | Green      | Reachable directly via jumpbox (no proxy)                   |
| `INTERNAL (PROXY)` | Blue       | Only reachable via corporate proxy                          |
| `DIA / HOST NET`   | Yellow/Red | Must bypass jumpbox and go direct from your machine         |
| `SOCKS BLOCKED`    | Magenta    | Jumpbox cannot reach - likely proxy required or missing PAC |
| `EXTERNAL`         | Cyan       | Public and reachable without special routing                |
| `UNRESOLVABLE`     | Dim        | No DNS and no connectivity                                  |

---

## Key behaviour (important)

### DNS is NOT authoritative

This tool does **not** assume:

```text
No DNS = dead domain
```

Instead:

```text
No DNS + Proxy works = PROXY-ONLY DOMAIN
```

---

## Example output

```text
portal.internal.local         [INTERNAL]
├── assets.cdnprovider.net    [INTERNAL (PROXY)]
├── static.cdnprovider.net    [INTERNAL (PROXY)]
└── auth.internal.local       [INTERNAL]
    ├── login.microsoftonline.com  [DIA / HOST NET]
    ├── aadcdn.msauth.net          [DIA / HOST NET]
    ├── aadcdn.msftauth.net        [DIA / HOST NET]
    ├── msftauth.net               [DIA / HOST NET]
    └── graph.microsoft.com        [DIA / HOST NET]
```

### Why this matters

* App traffic → VPN
* CDN traffic → proxy
* SSO traffic → DIA

If routed incorrectly, authentication and application behaviour will break.

---

## Setup

```bash
pip install -r requirements.txt
```

Python 3.11+

Start your SOCKS tunnel:

```bash
ssh -D 1080 -N -q user@jumpbox
```

---

## Usage

### Interactive (recommended)

```bash
python IsItProxy.py
```

Prompts for:

* SOCKS proxy
* PAC file (optional)
* Corporate proxy (important)
* Target URL

---

### Non-interactive

```bash
python IsItProxy.py \
    --url https://portal.corp.local \
    --socks-port 1080 \
    --pac-file proxy.pac
```

---

### Examples

```bash
# SOCKS + PAC
python IsItProxy.py --url https://portal --socks-port 1080 --pac-file proxy.pac

# Fetch PAC via tunnel
python IsItProxy.py --url https://portal --socks-port 1080 \
    --pac-url http://wpad.corp.local/proxy.pac

# Add custom DIA domains
python IsItProxy.py --url https://portal --socks-port 1080 \
    --dia-domain okta.com

# No SOCKS (local testing)
python IsItProxy.py --url https://portal --no-socks

# DNS only
python IsItProxy.py --url portal.local --depth 0
```

---

## Options

| Flag               | Description                |
| ------------------ | -------------------------- |
| `--url`            | Target URL or hostname     |
| `--socks-port`     | SOCKS5 port                |
| `--no-socks`       | Disable SOCKS              |
| `--pac-file`       | Local PAC file             |
| `--pac-url`        | Fetch PAC via HTTP         |
| `--dia-domain`     | Add DIA domain             |
| `--dia-file`       | File of DIA domains        |
| `--depth`          | Crawl depth                |
| `--timeout`        | HTTP timeout               |
| `--no-builtin-dia` | Disable Microsoft defaults |

---

## Burp Suite integration

Generates:

```text
IsItProxy_burp_<target>_<timestamp>.json
```

### Routing

| Type             | Behaviour                |
| ---------------- | ------------------------ |
| INTERNAL         | Routed via SOCKS         |
| INTERNAL (PROXY) | Routed via SOCKS + proxy |
| DIA              | Direct from your machine |
| EXTERNAL         | Direct from your machine |

---

### Import

**Burp 2023+**

```
Settings → Project → Load project options file
```

**Older versions**

```
Project options → Misc → Restore
```

---

### Important

Do NOT enable a global SOCKS proxy in Burp.

This breaks:

* DIA traffic
* external access

---

## PAC support

Parses:

* `shExpMatch`
* `dnsDomainIs`
* `host ==`

Handles:

* nested conditions
* if/else chains

Limitations:

* runtime logic may not fully resolve
* unmatched rules are reported

---

## Built-in DIA domains

Includes common Microsoft / Microsoft Entra ID / Azure domains by default.

Extend via:

```bash
--dia-domain
--dia-file
--pac-file
```

---

## Limitations

* No full JavaScript execution (dynamic SPAs may hide endpoints)
* Proxy authentication (NTLM/Kerberos) not fully supported yet
* Proxy success ≠ full app access (login pages may still appear)
* Deep crawling increases runtime

---

## TODO

* [ ] PAC auto-discovery (WPAD)
* [ ] Proxy authentication support
* [ ] IdP detection (Okta / Entra / Ping)
* [ ] Smarter Burp routing rules

---

## TL;DR

This tool answers:

> “How must this domain be routed to actually work?”

Not:

> “Does DNS resolve?”

---

## Why this matters

Without this:

* Proxy-only domains look “dead”
* SSO breaks unpredictably
* Burp routing becomes guesswork

With this:

* Routing is correct first time
* Burp works reliably
* You focus on testing, not networking
