# IsItProxy

Domain routing analyser for pentest engagements. Runs from the local machine, uses an SSH SOCKS proxy to see domains from the jumpbox's perspective, then tells Burp Suite exactly how to route each one.

Built for engagements where the tester VPNs into an internal Kali jumpbox that has no direct internet - only a corporate proxy - but where some traffic (Microsoft/Entra SSO, corporate CDNs) must go Direct to Internet via a PAC file the jumpbox can't use.

---

## How it works

1. **SOCKS setup** - connects through `ssh -D 1080 user@jumpbox` to fetch pages from the jumpbox's perspective, not the tester's local machine
2. **PAC file parsing** - load a PAC file (local path or URL) to automatically identify which domains are `DIRECT` (DIA) vs `PROXY`; no need to know your PAC contents in advance
3. **Nameserver lookup** - queries NS records for the root domain to identify who controls DNS
4. **Dual DNS resolution** - resolves every domain via local DNS and via `8.8.8.8`; a private local IP or local-only resolution flags it as internal (different public IPs are anycast/geo-DNS, not split-horizon)
5. **Deep crawl** - follows every domain referenced in the page including linked JS and CSS files:
   - HTML attributes (`href`, `src`, `action`, `data-*`)
   - Inline `<script>` and `<style>` blocks
   - External JS files - fetched and scanned for `fetch()`, `axios`, `XMLHttpRequest`, string URLs
   - External CSS files - fetched and scanned for `url()`, `@import`
   - Response headers (`Content-Security-Policy`, `Link`, `Location`, `Refresh`)
   - HTTP redirect chains
6. **Burp Suite config** - writes a ready-to-import JSON file that routes internal domains via SOCKS and lets everything else go direct from the tester's machine

---

## Classification

| Label | Colour | Meaning |
|---|---|---|
| `DIA / HOST NET` | Yellow/Red | Known DIA domain - Burp routes direct from tester's machine |
| `SOCKS BLOCKED` | Magenta | Public IP, jumpbox couldn't reach it - likely unlisted DIA or missing proxy config |
| `INTERNAL` | Green | Private IP or local-only DNS - Burp routes via SOCKS tunnel |
| `EXTERNAL` | Cyan | Public IP reachable via SOCKS - Burp routes direct from tester's machine |
| `UNRESOLVABLE` | Dim | No DNS from either perspective |

`SOCKS BLOCKED` means the jumpbox couldn't connect but it has a consistent public IP. Without a PAC file loaded the tool can't tell if this is DIA or a proxy gap - load your PAC with `--pac-file` or `--pac-url` to resolve the ambiguity automatically.

---

## Setup

```bash
pip install -r requirements.txt
```

Python 3.11+ required.

Before running, open a separate terminal and create the SSH SOCKS proxy:

```bash
ssh -D 1080 -N -q user@jumpbox-ip
```

---

## Usage

### Interactive

```bash
python IsItProxy.py
```

Walks through SOCKS proxy setup, optional PAC file loading, and target entry. Recommended for first use.

### Non-interactive

```bash
# SOCKS + local PAC file
python IsItProxy.py --url https://portal.corp.local --socks-port 1080 \
    --pac-file /path/to/proxy.pac

# SOCKS + fetch PAC from internal WPAD server through the tunnel
python IsItProxy.py --url https://portal.corp.local --socks-port 1080 \
    --pac-url http://wpad.corp.local/proxy.pac

# PAC + extra domains not in the PAC
python IsItProxy.py --url https://portal.corp.local --socks-port 1080 \
    --pac-file proxy.pac --dia-domain okta.com --dia-domain auth0.com

# No SOCKS (local DNS only, results are from tester's perspective)
python IsItProxy.py --url https://portal.corp.local --no-socks

# DNS and NS lookup only, no HTTP crawl
python IsItProxy.py --url portal.corp.local --no-socks --depth 0

# Deeper crawl
python IsItProxy.py --url https://portal.corp.local --socks-port 1080 --depth 3 --timeout 15

# PAC-only DIA list, skip built-in Microsoft domains
python IsItProxy.py --url https://portal.corp.local --socks-port 1080 \
    --pac-file proxy.pac --no-builtin-dia
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--url` | interactive | Target URL or bare hostname |
| `--socks-port PORT` | interactive | SOCKS5 proxy port on `127.0.0.1` |
| `--no-socks` | off | Skip SOCKS, use local DNS only |
| `--pac-file FILE` | - | Local PAC file to parse for DIA domains |
| `--pac-url URL` | - | URL of PAC file to fetch (goes via SOCKS if set) |
| `--no-builtin-dia` | off | Exclude built-in Microsoft DIA list; use PAC/custom only |
| `--dia-domain DOMAIN` | - | Additional DIA apex domain, repeatable |
| `--dia-file FILE` | - | Text file of DIA apex domains, one per line (`#` = comment) |
| `--depth N` | `2` | Crawl depth - `0` = DNS + NS only, no HTTP |
| `--timeout SEC` | `10` | Per-request HTTP timeout in seconds |

---

## PAC file support

PAC files are JavaScript. The parser extracts `shExpMatch`, `dnsDomainIs`, and `host ==` conditions and maps each to its `return "DIRECT"` or `return "PROXY ..."` outcome using brace-depth tracking. Flat and nested if/else chains are both handled.

PAC files with runtime logic (e.g. IP-range conditionals that affect which domains go DIRECT) may not be fully parsed - the tool reports how many conditions it couldn't classify. Any remaining `SOCKS BLOCKED` domains after loading a PAC are worth reviewing manually.

---

## Burp Suite config

After each run the script writes **`IsItProxy_burp_<host>_<timestamp>.json`** automatically.

### Routing strategy

| Domain type | What Burp does |
|---|---|
| `INTERNAL` | Upstream SOCKS5 rule → `127.0.0.1:<socks_port>` - routes via SSH tunnel to jumpbox |
| `DIA / HOST NET` | No rule - Burp connects directly from the tester's machine |
| `EXTERNAL` | No rule - Burp connects directly from the tester's machine |

No proxy is needed on the jumpbox. Internal traffic flows via the SOCKS tunnel; everything else goes direct from the tester's machine without touching the jumpbox at all.

> **Do not enable a global SOCKS proxy in Burp.** The upstream rules handle internal routing. A global SOCKS would push DIA and external traffic through the jumpbox, breaking those requests.

### Importing

**Burp Suite 2023+**
Gear icon → Project → **Load project options file** → select the `.json` file

**Burp Suite 2022 and earlier**
Project options → Misc → Save/restore → **Restore project options** → select the `.json` file

---

## Built-in DIA domains

The following apex domains (and all subdomains) are flagged as DIA by default. Extend via `--dia-domain`, `--dia-file`, or `--pac-file`.

`microsoft.com` · `microsoftonline.com` · `live.com` · `outlook.com` · `office.com` · `office365.com` · `sharepoint.com` · `onmicrosoft.com` · `azure.com` · `azureedge.net` · `azurewebsites.net` · `windows.net` · `windowsazure.com` · `sts.windows.net` · `msauth.net` · `msftauth.net` · `msidentity.com` · `graph.microsoft.com` · `teams.microsoft.com` · `skype.com` · `visualstudio.com` · `trafficmanager.net` · `1drv.com` · `lync.com` · `msocsp.com` · `msocdn.com` · `msappproxy.net`

---

## Limitations

- JavaScript-rendered content (SPAs that build URLs at runtime via `eval` or string concatenation) cannot be fully discovered statically
- Pages behind SSO redirect to a login domain - this is still useful, as it surfaces the Microsoft/IdP domains involved
- Higher crawl depths increase request count and runtime significantly; start at the default of `2`
- The SOCKS proxy must already be running before the script starts
