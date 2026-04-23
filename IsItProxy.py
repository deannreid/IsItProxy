#!/usr/bin/env python3
"""
IsItProxy - Jumpbox domain routing analyser for pentest engagements.
Runs from local machine, using an SSH SOCKS proxy to
see domains from the jumpbox's perspective.

Author : https://github.com/deannreid
"""

import getpass
import ipaddress
import json
import re
import socket
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Optional, Union
from urllib.parse import urlparse

import dns.resolver
import requests
import urllib3
from bs4 import BeautifulSoup
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from requests_ntlm import HttpNtlmAuth as _NtlmAuth
    _HAS_NTLM = True
except ImportError:
    _HAS_NTLM = False

console = Console()

############################# Built-in DIA apex domains #########################
# Microsoft / Entra SSO domains that are almost universally DIA.
# Users extend this list via --dia-domain, --dia-file, or --pac-file/--pac-url.
#################################################################################

_BUILTIN_DIA: dict[str, str] = {
    "microsoft.com":            "Microsoft / Entra SSO",
    "microsoftonline.com":      "Microsoft / Entra SSO",
    "live.com":                 "Microsoft / Entra SSO",
    "outlook.com":              "Microsoft",
    "office.com":               "Microsoft 365",
    "office365.com":            "Microsoft 365",
    "sharepoint.com":           "Microsoft SharePoint",
    "onmicrosoft.com":          "Microsoft tenant domain",
    "azure.com":                "Microsoft Azure",
    "azureedge.net":            "Microsoft Azure CDN",
    "azurewebsites.net":        "Microsoft Azure",
    "windows.net":              "Microsoft Azure",
    "windowsazure.com":         "Microsoft Azure",
    "sts.windows.net":          "Microsoft STS",
    "msauth.net":               "Microsoft Auth CDN",
    "msftauth.net":             "Microsoft Auth CDN",
    "aadcdn.msftauthimages.net":"Microsoft Auth CDN",
    "aadcdn.msauth.net":        "Microsoft Auth CDN",
    "aadcdn.msftauth.net":      "Microsoft Auth CDN",
    "msidentity.com":           "Microsoft Identity",
    "msauthimages.net":         "Microsoft Auth CDN",
    "msftconnecttest.com":      "Microsoft connectivity check",
    "msftncsi.com":             "Microsoft NCSI",
    "msocsp.com":               "Microsoft OCSP",
    "msocdn.com":               "Microsoft CDN",
    "msappproxy.net":           "Microsoft App Proxy",
    "visualstudio.com":         "Azure DevOps",
    "trafficmanager.net":       "Azure Traffic Manager",
    "1drv.com":                 "OneDrive",
    "skype.com":                "Microsoft Skype",
    "lync.com":                 "Microsoft Lync",
    "teams.microsoft.com":      "Microsoft Teams",
    "graph.microsoft.com":      "Microsoft Graph API",
    "login.windows.net":        "Microsoft Login",
    "login.live.com":           "Microsoft Login",
    "account.microsoft.com":    "Microsoft Account",
    "signup.microsoft.com":     "Microsoft Signup",
}

_PRIVATE_NETS: list = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fc00::/7"),
]

_URL_RE     = re.compile(r'https?://([a-zA-Z0-9._-]+[a-zA-Z0-9])', re.I)
_CSS_URL_RE = re.compile(r"""url\s*\(\s*['"]?(https?://[^'")\s]+)""", re.I)
_CSS_IMP_RE = re.compile(r"""@import\s+['"]?(https?://[^'";\s]+)""", re.I)
_JS_API_RE  = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|open)\s*\(\s*['"`](https?://[^'"`;,\s]+)""", re.I
)

_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


############################# Routing classification ###########################

class Routing(Enum):
    DIA_REQUIRED  = auto()  # known DIA domain → must use host network, not VPN
    SOCKS_BLOCKED = auto()  # public IP, SOCKS unreachable → possible unlisted DIA
    INTERNAL      = auto()  # private IP or split-horizon DNS → use VPN/jumpbox
    INTERNAL_PROXY= auto()  # private IP but also reachable via SOCKS → use VPN, but proxy on jumpbox if needed
    EXTERNAL      = auto()  # public IP reachable via SOCKS → needs corp proxy on jumpbox or host
    UNRESOLVABLE  = auto()  # no DNS from either perspective

_ROUTING_META: dict[Routing, tuple[str, str, str, str]] = {
    Routing.DIA_REQUIRED:  ("bold yellow", "bold red",  "DIA / HOST NET",  "Route via host network - NOT through VPN"),
    Routing.SOCKS_BLOCKED: ("bold magenta","magenta",   "SOCKS BLOCKED",   "Jumpbox cannot reach - possible unlisted DIA"),
    Routing.INTERNAL:      ("bold green",  "green",     "INTERNAL",        "Accessible via jumpbox VPN"),
    Routing.INTERNAL_PROXY: ("bold blue",  "blue",      "INTERNAL PROXY",   "Accessible via jumpbox VPN with proxy"),
    Routing.EXTERNAL:      ("bold cyan",   "cyan",      "EXTERNAL",        "Public internet domain"),
    Routing.UNRESOLVABLE:  ("dim white",   "dim",       "UNRESOLVABLE",    "No DNS from either perspective"),
}


############################# Data model #################################

@dataclass
class DNSInfo:
    local_ip:     Optional[str] = None
    external_ip:  Optional[str] = None
    nameservers:  list[str]     = field(default_factory=list)
    is_private:   bool          = False
    split_horizon: bool         = False
    ip_mismatch:  bool          = False


@dataclass
class DomainResult:
    hostname:     str
    routing:      Routing
    dns:          DNSInfo
    is_dia:       bool           = False
    dia_reason:   str            = ""
    via_socks:    Optional[bool] = None   # reachable via SSH SOCKS / jumpbox
    via_direct:   Optional[bool] = None   # reachable directly (no proxy, no SOCKS)
    via_proxy:    Optional[bool] = None   # reachable via corporate proxy
    fetch_error:  Optional[str]  = None
    direct_error: Optional[str]  = None
    proxy_error:  Optional[str]  = None
    proxy_page:   Optional[str]  = None   # proxy scan/block page reason if detected
    children:     dict           = field(default_factory=dict)


@dataclass
class ProxyConfig:
    """Corporate proxy settings including optional authentication."""
    url:          str
    username:     Optional[str]       = None
    password:     Optional[str]       = None
    auth_type:    str                 = "none"   # "none", "basic", "ntlm"
    ntlm_domain:  Optional[str]       = None     # Windows domain for NTLM (e.g. CORP)
    ntlm_dc:      Optional[str]       = None     # Domain controller hostname (informational)
    cert_path:    Union[bool, str]    = False    # CA bundle path or False to skip verify


############################# PAC file parser ##############################

# PAC condition matchers
_PAC_SHEXP   = re.compile(r'shExpMatch\s*\(\s*(?:host|url)\s*,\s*["\']([^"\']+)["\']', re.I)
_PAC_DNSIS   = re.compile(r'dnsDomainIs\s*\(\s*host\s*,\s*["\']\.?([a-zA-Z0-9._-]+)["\']', re.I)
_PAC_HOSTEQ  = re.compile(r'\bhost\s*(?:==|===)\s*["\']([a-zA-Z0-9._-]+)["\']', re.I)
_PAC_RETURN  = re.compile(r'return\s+["\']?(DIRECT|PROXY[^;"\';\n]*|SOCKS[^;"\';\n]*)["\']?', re.I)


def _pac_pattern_to_apex(pattern: str) -> Optional[str]:
    """Convert a PAC glob/URL pattern to an apex domain string."""
    p = pattern.strip().lstrip("*. ")
    p = re.sub(r'^https?://', '', p, flags=re.I)
    p = p.split('/')[0].split('?')[0].split(':')[0].lower()
    if re.match(r'^[a-z0-9][a-z0-9._-]*\.[a-z]{2,}$', p):
        return p
    return None


def _strip_nested_braces(text: str) -> str:
    """Return text with all content inside nested {} removed."""
    out, depth = [], 0
    for ch in text:
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
        elif depth == 0:
            out.append(ch)
    return ''.join(out)


def _domains_from_condition(cond: str) -> list[str]:
    out: list[str] = []
    for m in _PAC_SHEXP.finditer(cond):
        a = _pac_pattern_to_apex(m.group(1))
        if a:
            out.append(a)
    for m in _PAC_DNSIS.finditer(cond):
        a = m.group(1).lower().lstrip('.')
        if '.' in a:
            out.append(a)
    for m in _PAC_HOSTEQ.finditer(cond):
        a = m.group(1).lower()
        if '.' in a:
            out.append(a)
    return out


def _parse_if_blocks(content: str) -> list[tuple[str, str]]:
    """
    Walk PAC JavaScript and return [(condition_text, return_action), ...].
    Uses brace-depth tracking so each condition is paired with its own block's
    immediate return (excluding nested sub-blocks).
    Recurses into nested blocks.
    """
    results: list[tuple[str, str]] = []
    i, n = 0, len(content)

    while i < n:
        m = re.search(r'\bif\s*\(', content[i:])
        if not m:
            break

        if_start   = i + m.start()
        paren_open = i + m.end() - 1   # index of the opening '('

        # Find the matching closing ')'
        depth, j = 1, paren_open + 1
        while j < n and depth:
            depth += (content[j] == '(') - (content[j] == ')')
            j += 1
        if depth:                       # unmatched, skip
            i = if_start + 1
            continue

        condition = content[paren_open + 1 : j - 1]

        # Skip whitespace to find '{'
        k = j
        while k < n and content[k] in ' \t\n\r':
            k += 1

        if k >= n or content[k] != '{':
            # Brace-less inline if:  if (cond) return "DIRECT";
            eol = content.find('\n', j)
            if eol == -1:
                eol = n
            rm = _PAC_RETURN.search(content[j:eol])
            if rm:
                results.append((condition, rm.group(1).strip().rstrip('"\'').strip()))
            i = eol
            continue

        # Find matching '}'
        brace_open = k
        depth, k = 1, brace_open + 1
        while k < n and depth:
            depth += (content[k] == '{') - (content[k] == '}')
            k += 1

        body = content[brace_open + 1 : k - 1]

        # Flat body (strip nested blocks) to find this block's own return
        flat = _strip_nested_braces(body)
        rm   = _PAC_RETURN.search(flat)
        if rm:
            results.append((condition, rm.group(1).strip().rstrip('"\'').strip()))

        # Recurse into nested blocks
        results.extend(_parse_if_blocks(body))

        i = k

    return results


@dataclass
class PacResult:
    direct_domains: dict[str, str]   # apex -> "PAC file: DIRECT"
    proxy_domains:  dict[str, str]   # apex -> "PAC file: PROXY ..."
    unmatched_count: int              # conditions where action couldn't be determined
    source: str                       # path or URL used


def parse_pac_content(content: str, source: str) -> PacResult:
    """
    Parse PAC file text and return classified domain sets.
    DIRECT entries populate direct_domains (added to DIA set).
    PROXY entries populate proxy_domains (for reference only).
    """
    direct: dict[str, str] = {}
    proxy:  dict[str, str] = {}
    unmatched = 0

    blocks = _parse_if_blocks(content)

    for condition, action in blocks:
        domains = _domains_from_condition(condition)
        if not domains:
            continue
        action_up = action.upper()
        for domain in domains:
            if action_up == "DIRECT":
                direct.setdefault(domain, f"PAC: DIRECT ({source})")
            elif action_up.startswith(("PROXY", "SOCKS")):
                proxy.setdefault(domain, f"PAC: {action} ({source})")
            else:
                unmatched += 1

    return PacResult(
        direct_domains=direct,
        proxy_domains=proxy,
        unmatched_count=unmatched,
        source=source,
    )


def load_pac(source: str, socks_port: Optional[int] = None) -> str:
    """Fetch PAC content from a local file path or HTTP/HTTPS URL."""
    if source.startswith(("http://", "https://")):
        sess = _make_session(socks_port)
        resp = sess.get(source, timeout=15, verify=False)
        resp.raise_for_status()
        return resp.text
    return Path(source).read_text(encoding="utf-8", errors="replace")


############################# DIA domain helpers #############################

def build_dia_set(
    extra_domains: list[str],
    dia_file:      Optional[Path],
    pac_result:    Optional[PacResult],
    include_builtin: bool = True,
) -> dict[str, str]:
    combined: dict[str, str] = {}

    if include_builtin:
        combined.update(_BUILTIN_DIA)

    if pac_result:
        combined.update(pac_result.direct_domains)

    if dia_file:
        try:
            for line in dia_file.read_text().splitlines():
                apex = line.strip().lower().lstrip("*.")
                if apex and not apex.startswith("#"):
                    combined[apex] = "Custom DIA (from file)"
        except OSError as exc:
            console.print(f"[yellow]Warning: could not read --dia-file: {exc}[/yellow]")

    for raw in extra_domains:
        apex = raw.lower().strip().lstrip("*.")
        if apex:
            combined[apex] = "Custom DIA (user-specified)"

    return combined


def check_dia(hostname: str, dia_set: dict[str, str]) -> tuple[bool, str]:
    h = hostname.lower().lstrip(".")
    for apex, reason in dia_set.items():
        if h == apex or h.endswith("." + apex):
            return True, reason
    return False, ""


############################# DNS helpers ################################

_ext_resolver = dns.resolver.Resolver()
_ext_resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
_ext_resolver.timeout  = 4
_ext_resolver.lifetime = 4


def resolve_local(hostname: str) -> Optional[str]:
    try:
        return socket.gethostbyname(hostname)
    except (socket.gaierror, OSError):
        return None


def resolve_external(hostname: str) -> Optional[str]:
    try:
        return str(_ext_resolver.resolve(hostname, "A")[0])
    except Exception:
        return None


def get_nameservers(hostname: str) -> list[str]:
    parts = hostname.split(".")
    for i in range(len(parts) - 1):
        try:
            ans = _ext_resolver.resolve(".".join(parts[i:]), "NS")
            return sorted(str(r).rstrip(".") for r in ans)
        except Exception:
            continue
    return []


def ip_is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def classify(
    dns:              DNSInfo,
    is_dia:           bool,
    via_socks:        Optional[bool],
    via_proxy:        Optional[bool],
    socks_configured: bool = True,
) -> Routing:
    if is_dia:
        return Routing.DIA_REQUIRED
    if via_socks:
        return Routing.INTERNAL
    if via_proxy:
        return Routing.INTERNAL_PROXY
    if dns.is_private or dns.split_horizon:
        return Routing.INTERNAL
    if not dns.local_ip and not dns.external_ip:
        return Routing.UNRESOLVABLE
    # Has resolvable public DNS
    if not socks_configured:
        # No jumpbox to test from — it's a regular public internet domain
        return Routing.EXTERNAL
    # SOCKS was configured but couldn't reach this domain
    return Routing.SOCKS_BLOCKED


############################# Content extraction #############################

def _hostnames_from_text(text: str) -> set[str]:
    return {m.group(1).lower() for m in _URL_RE.finditer(text)}


def _hostnames_from_css(text: str) -> set[str]:
    out: set[str] = set()
    for pat in (_CSS_URL_RE, _CSS_IMP_RE):
        for m in pat.finditer(text):
            p = urlparse(m.group(1))
            if p.hostname:
                out.add(p.hostname.lower())
    return out


def _hostnames_from_js(text: str) -> set[str]:
    out: set[str] = set()
    for m in _JS_API_RE.finditer(text):
        p = urlparse(m.group(1))
        if p.hostname:
            out.add(p.hostname.lower())
    out |= _hostnames_from_text(text)
    return out


def _safe_fetch(url: str, session: requests.Session, timeout: int) -> Optional[str]:
    try:
        return session.get(url, timeout=timeout, verify=False, allow_redirects=True).text
    except Exception:
        return None


def extract_domains(
    response: requests.Response,
    session:  requests.Session,
    timeout:  int,
) -> set[str]:
    """
    Extract all hostnames from an HTTP response.
    Deep-fetches up to 25 linked JS and 15 CSS files to find domains
    referenced in those resources.
    """
    domains:  set[str]  = set()
    js_urls:  list[str] = []
    css_urls: list[str] = []

    for r in list(response.history) + [response]:
        p = urlparse(r.url)
        if p.hostname:
            domains.add(p.hostname.lower())

    for hdr in ("Location", "Content-Security-Policy", "Link", "Refresh"):
        val = response.headers.get(hdr, "")
        if val:
            domains |= _hostnames_from_text(val)

    ctype = response.headers.get("Content-Type", "")

    if "html" in ctype:
        try:
            soup = BeautifulSoup(response.content, "lxml")
            for tag in soup.find_all(True):
                for attr in ("href", "src", "action", "data-src", "data-href",
                             "data-url", "data-api", "data-endpoint", "content"):
                    val = tag.get(attr, "")
                    if isinstance(val, str) and val.startswith("http"):
                        p = urlparse(val)
                        if p.hostname:
                            domains.add(p.hostname.lower())

                if tag.name == "script":
                    src = tag.get("src", "")
                    if src and src.startswith("http"):
                        js_urls.append(src)
                    elif tag.string:
                        domains |= _hostnames_from_js(tag.string)

                if tag.name == "link":
                    rel = tag.get("rel", [])
                    if not isinstance(rel, list):
                        rel = [rel]
                    if "stylesheet" in rel or "preload" in rel:
                        href = tag.get("href", "")
                        if href and href.startswith("http"):
                            css_urls.append(href)

                if tag.name == "style" and tag.string:
                    domains |= _hostnames_from_css(tag.string)

                if tag.name == "meta" and tag.get("http-equiv", "").lower() == "refresh":
                    m2 = re.search(r"url=(.+)", tag.get("content", ""), re.I)
                    if m2:
                        p = urlparse(m2.group(1).strip())
                        if p.hostname:
                            domains.add(p.hostname.lower())
        except Exception:
            pass

    elif "javascript" in ctype or "ecmascript" in ctype:
        try:
            domains |= _hostnames_from_js(response.text)
        except Exception:
            pass
    elif "css" in ctype:
        try:
            domains |= _hostnames_from_css(response.text)
        except Exception:
            pass
    else:
        try:
            domains |= _hostnames_from_text(response.text)
        except Exception:
            pass

    for url in js_urls[:25]:
        text = _safe_fetch(url, session, timeout)
        if text:
            domains |= _hostnames_from_js(text)

    for url in css_urls[:15]:
        text = _safe_fetch(url, session, timeout)
        if text:
            domains |= _hostnames_from_css(text)

    domains.discard("")
    return domains

######## Proxy session helper #############################

# Patterns that indicate a proxy intercepted the connection and returned its own page
_PROXY_SCAN_SIGS: list[tuple[str, str]] = [
    ("fortiguard",         "fortiguard web filtering"),
    ("bluecoat",           "bluecoat systems"),
    ("symantec proxy",     "symantec web security service"),
    ("zscaler",            "zscaler internet security"),
    ("cisco umbrella",     "cisco umbrella"),
    ("cisco wsa",          "cisco web security appliance"),
    ("squid",              "access control configuration prevents"),
    ("mcafee",             "mcafee web gateway"),
    ("websense",           "websense"),
    ("clearswift",         "clearswift"),
    ("iboss",              "iboss cloud"),
    ("barracuda",          "barracuda web filter"),
    ("sophos",             "sophos web appliance"),
    ("proxy auth",         "proxy authentication required"),
    ("palo alto",          "pan-db url filtering"),
]

_PROXY_SERVER_SIGS = {"squid", "bluecoat", "fortigate", "zscaler", "cisco", "mcafee", "iboss"}


def _is_proxy_error_page(resp: requests.Response) -> tuple[bool, str]:
    """Detect whether the response is a proxy scan/block/auth page rather than the real target."""
    if resp.status_code == 407:
        return True, "Proxy authentication required (HTTP 407)"

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    if "x-squid-error" in headers_lower:
        return True, f"Squid proxy error: {headers_lower['x-squid-error']}"

    if "via" in headers_lower:
        via = headers_lower["via"].lower()
        for sig in _PROXY_SERVER_SIGS:
            if sig in via:
                return True, f"Proxy detected via Via header ({headers_lower['via']})"

    server = headers_lower.get("server", "").lower()
    for sig in _PROXY_SERVER_SIGS:
        if sig in server:
            return True, f"Proxy server signature in headers ({headers_lower.get('server','')})"

    try:
        body = resp.text[:8000].lower()
    except Exception:
        return False, ""

    for name, pattern in _PROXY_SCAN_SIGS:
        if pattern in body:
            return True, f"Proxy scan/block page ({name})"

    return False, ""


def _make_proxy_session(cfg: ProxyConfig) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = _UA
    s.proxies = {
        "http":  cfg.url,
        "https": cfg.url,
    }
    s.verify    = cfg.cert_path
    s.trust_env = False

    if cfg.auth_type == "basic" and cfg.username:
        s.auth = requests.auth.HTTPProxyAuth(cfg.username, cfg.password or "")
    elif cfg.auth_type == "ntlm" and _HAS_NTLM and cfg.username:
        ntlm_user = f"{cfg.ntlm_domain}\\{cfg.username}" if cfg.ntlm_domain else cfg.username
        s.auth = _NtlmAuth(ntlm_user, cfg.password or "")

    return s

############################# Core analyser ###############################

def analyse(
    hostname:      str,
    depth:         int,
    max_depth:     int,
    visited:       set[str],
    socks_session: Optional[requests.Session],
    timeout:       int,
    dia_set:       dict[str, str],
    fetch_ns:      bool = False,
    proxy_cfg:     Optional[ProxyConfig] = None,
) -> DomainResult:

    visited.add(hostname)
    is_dia, dia_reason = check_dia(hostname, dia_set)

    local_ip    = resolve_local(hostname)
    external_ip = resolve_external(hostname)
    ns          = get_nameservers(hostname) if fetch_ns else []
    priv = ip_is_private(local_ip) if local_ip else False

    split = bool((local_ip and priv) or (local_ip and not external_ip))
    mismatch = bool(local_ip and external_ip and local_ip != external_ip and not priv)

    dns_info = DNSInfo(
        local_ip=local_ip,
        external_ip=external_ip,
        nameservers=ns,
        is_private=priv,
        split_horizon=split,
        ip_mismatch=mismatch,
    )

    result = DomainResult(
        hostname=hostname,
        routing=Routing.UNRESOLVABLE,
        dns=dns_info,
        is_dia=is_dia,
        dia_reason=dia_reason,
    )

    socks_configured = socks_session is not None

    if is_dia:
        result.routing = Routing.DIA_REQUIRED
        return result

    if depth >= max_depth:
        # No HTTP tests at max depth — classify purely on DNS
        result.routing = classify(dns_info, False, None, None, socks_configured)
        return result

    url          = f"https://{hostname}"
    fetched_resp = None
    fetch_session = socks_session  # session used for child enumeration

    # ── STEP 1: SOCKS / JUMPBOX ──────────────────────────────────────────────
    if socks_session:
        try:
            resp = socks_session.get(url, timeout=timeout, verify=False)
            is_scan, reason = _is_proxy_error_page(resp)
            if is_scan:
                result.via_socks = False
                result.fetch_error = f"Proxy page via SOCKS: {reason}"
            else:
                result.via_socks = True
                fetched_resp     = resp
        except Exception as exc:
            result.via_socks  = False
            result.fetch_error = str(exc)[:80]

    # ── STEP 2: DIRECT INTERNET (no proxy, no SOCKS) ─────────────────────────
    if fetched_resp is None:
        try:
            direct_session = requests.Session()
            direct_session.headers["User-Agent"] = _UA
            direct_session.trust_env = False
            resp = direct_session.get(url, timeout=timeout, verify=False)
            is_scan, reason = _is_proxy_error_page(resp)
            if is_scan:
                result.via_direct  = False
                result.direct_error = f"Proxy page on direct: {reason}"
            else:
                result.via_direct = True
                fetched_resp      = resp
                fetch_session     = direct_session
        except Exception as exc:
            result.via_direct  = False
            result.direct_error = str(exc)[:80]

    # ── STEP 3: CORPORATE PROXY ───────────────────────────────────────────────
    if proxy_cfg:
        try:
            proxy_session = _make_proxy_session(proxy_cfg)
            resp = proxy_session.get(url, timeout=timeout, verify=proxy_cfg.cert_path)
            is_scan, reason = _is_proxy_error_page(resp)
            if is_scan:
                result.via_proxy  = False
                result.proxy_error = str(reason)[:120]
                result.proxy_page  = reason
            else:
                result.via_proxy = True
                if fetched_resp is None:
                    fetched_resp  = resp
                    fetch_session = proxy_session
        except Exception as exc:
            result.via_proxy  = False
            result.proxy_error = str(exc)[:120]

    result.routing = classify(dns_info, is_dia, result.via_socks, result.via_proxy, socks_configured)

    if fetched_resp and fetch_session:
        for child in extract_domains(fetched_resp, fetch_session, timeout):
            if child and child != hostname and child not in visited:
                result.children[child] = analyse(
                    child,
                    depth + 1,
                    max_depth,
                    visited,
                    socks_session,
                    timeout,
                    dia_set,
                    proxy_cfg=proxy_cfg,
                )

    return result

############################# Rendering #################################

def _domain_label(r: DomainResult) -> Text:
    style, tag_style, tag, note = _ROUTING_META[r.routing]
    t = Text()
    t.append(r.hostname, style=style)
    t.append(f"  [{tag}]", style=tag_style)
    if r.dns.local_ip:
        if r.dns.split_horizon:
            # Private IP locally or local-only resolution - genuinely internal
            t.append(f"  {r.dns.local_ip}(local) / {r.dns.external_ip or 'no public DNS'}(ext)", style="dim magenta")
        elif r.dns.ip_mismatch:
            # Different public IPs - just anycast/geo-DNS, informational only
            t.append(f"  {r.dns.local_ip}", style="dim")
            t.append(f"  [anycast - ext:{r.dns.external_ip}]", style="dim blue")
        else:
            t.append(f"  {r.dns.local_ip}", style="dim")
    t.append(f"  {note}", style="italic dim")
    return t


def _build_tree(result: DomainResult, node: Tree) -> None:
    for child in sorted(result.children.values(), key=lambda r: r.hostname):
        child_node = node.add(_domain_label(child))
        if child.fetch_error:
            child_node.add(Text(f"  ⚠  SOCKS: {child.fetch_error}", style="dim red"))
        if child.direct_error:
            child_node.add(Text(f"  ⚠  Direct: {child.direct_error}", style="dim yellow"))
        if child.proxy_page:
            child_node.add(Text(f"  ⚠  Proxy intercepted: {child.proxy_page}", style="dim magenta"))
        elif child.proxy_error:
            child_node.add(Text(f"  ⚠  Proxy: {child.proxy_error}", style="dim magenta"))
        if child.children:
            _build_tree(child, child_node)


def _collect_all(r: DomainResult, acc: dict) -> None:
    acc[r.hostname] = r
    for child in r.children.values():
        _collect_all(child, acc)


def print_pac_summary(pac: PacResult) -> None:
    console.print()
    console.print(Panel(
        f"[bold white]PAC File Analysis[/bold white]  [dim]{pac.source}[/dim]\n\n"
        f"[bold green]{len(pac.direct_domains)}[/bold green] DIRECT (DIA) domains found  "
        f"[bold cyan]{len(pac.proxy_domains)}[/bold cyan] PROXY domains found",
        box=box.ROUNDED,
        style="blue",
    ))

    if pac.direct_domains:
        tbl = Table(box=box.SIMPLE, header_style="bold green", title="[green]DIRECT (DIA) domains from PAC[/green]")
        tbl.add_column("Apex domain", style="yellow", no_wrap=True)
        for d in sorted(pac.direct_domains):
            tbl.add_row(d)
        console.print(tbl)

    if pac.proxy_domains:
        tbl = Table(box=box.SIMPLE, header_style="bold cyan", title="[cyan]PROXY domains from PAC (reference)[/cyan]")
        tbl.add_column("Apex domain",  style="cyan",  no_wrap=True)
        tbl.add_column("Action",       style="dim")
        for d in sorted(pac.proxy_domains):
            tbl.add_row(d, pac.proxy_domains[d].split("(")[0].strip())
        console.print(tbl)

    if pac.unmatched_count:
        console.print(f"[dim]  {pac.unmatched_count} condition(s) could not be classified - review the PAC file manually.[/dim]")
    console.print()


def print_results(
    root:       DomainResult,
    input_url:  str,
    socks_port: Optional[int],
    dia_set:    dict[str, str],
    pac:        Optional[PacResult],
    proxy_cfg:  Optional[ProxyConfig] = None,
    socks_configured: bool = False,
) -> None:
    console.print()
    socks_label  = f"SOCKS5  127.0.0.1:{socks_port} (jumpbox)" if socks_port else "none"
    pac_label    = pac.source if pac else "none"
    custom_dia   = [k for k, v in dia_set.items() if "Custom" in v]

    if proxy_cfg:
        auth_detail = ""
        if proxy_cfg.auth_type == "ntlm":
            dc_note = f" DC={proxy_cfg.ntlm_dc}" if proxy_cfg.ntlm_dc else ""
            auth_detail = f"  [NTLM  user={proxy_cfg.username}  domain={proxy_cfg.ntlm_domain or '?'}{dc_note}]"
        elif proxy_cfg.auth_type == "basic":
            auth_detail = f"  [Basic  user={proxy_cfg.username}]"
        cert_note = f"  cert={proxy_cfg.cert_path}" if proxy_cfg.cert_path else "  SSL verify=off"
        proxy_label = f"{proxy_cfg.url}{auth_detail}{cert_note}"
    else:
        proxy_label = "none"

    header = (
        f"[bold white]IsItProxy - Jumpbox Routing Analyser[/bold white]\n"
        f"[dim]Target      : {input_url}\n"
        f"SOCKS       : {socks_label}\n"
        f"Corp proxy  : {proxy_label}\n"
        f"PAC file    : {pac_label}"
    )
    if custom_dia:
        header += f"\nCustom DIA  : {', '.join(sorted(custom_dia))}"
    header += "[/dim]"

    console.print(Panel(header, box=box.DOUBLE_EDGE, style="bold blue"))

    if root.dns.nameservers:
        console.print()
        console.print(f"[bold]Nameservers for [cyan]{root.hostname}[/cyan]:[/bold]")
        for ns in root.dns.nameservers:
            console.print(f"  [dim]•[/dim] [white]{ns}[/white]")

    console.print()
    tree = Tree(_domain_label(root))
    if root.fetch_error:
        tree.add(Text(f"  ⚠  SOCKS: {root.fetch_error}", style="dim red"))
    if root.direct_error:
        tree.add(Text(f"  ⚠  Direct: {root.direct_error}", style="dim yellow"))
    if root.proxy_page:
        tree.add(Text(f"  ⚠  Proxy intercepted: {root.proxy_page}", style="dim magenta"))
    elif root.proxy_error:
        tree.add(Text(f"  ⚠  Proxy: {root.proxy_error}", style="dim magenta"))
    _build_tree(root, tree)
    console.print(tree)
    console.print()

    all_r: dict[str, DomainResult] = {}
    _collect_all(root, all_r)
    by_routing: dict[Routing, list[DomainResult]] = {r: [] for r in Routing}
    for r in all_r.values():
        by_routing[r.routing].append(r)

    ############################# DIA required #
    dia_list = sorted(by_routing[Routing.DIA_REQUIRED], key=lambda r: r.hostname)
    if dia_list:
        console.print(Rule(style="red"))
        console.print(Panel(
            "[bold red]ACTION REQUIRED - Burp Suite: Route via Host Network[/bold red]\n\n"
            "These domains bypass the corporate proxy (Direct Internet Access).\n"
            "The jumpbox VPN cannot carry this traffic. Configure Burp Suite\n"
            "to send them via your [bold]local network interface[/bold], not the tunnel.",
            style="red", box=box.ROUNDED,
        ))
        tbl = Table(box=box.SIMPLE, header_style="bold red", show_lines=False)
        tbl.add_column("Domain",      style="yellow",    no_wrap=True)
        tbl.add_column("Local IP",    style="dim yellow")
        tbl.add_column("Reason",      style="dim")
        tbl.add_column("Burp action", style="red")
        for r in dia_list:
            tbl.add_row(r.hostname, r.dns.local_ip or "-", r.dia_reason or "DIA",
                        "Upstream SOCKS / match-replace → local NIC")
        console.print(tbl)
        console.print()

    ############################# SOCKS blocked #
    blocked_list = sorted(by_routing[Routing.SOCKS_BLOCKED], key=lambda r: r.hostname)
    if blocked_list and socks_configured:
        console.print(Rule(style="magenta"))
        pac_hint = (
            "A PAC file was loaded - these were NOT in it as DIRECT. "
            "Check for dynamic PAC logic or conditional blocks."
            if pac else
            "No PAC file was loaded. Re-run with --pac-file or --pac-url to classify these automatically."
        )
        console.print(Panel(
            "[bold magenta]SOCKS Blocked - Jumpbox Cannot Reach These[/bold magenta]\n\n"
            "Public IP, consistent DNS, but the jumpbox could not connect via SOCKS.\n"
            "Possible causes:\n"
            "  • Domain goes DIA in the PAC file (not yet in the DIA list)\n"
            "  • Corporate proxy not configured for this domain on the jumpbox\n"
            "  • Firewall rule blocking outbound from jumpbox\n\n"
            f"[dim]{pac_hint}[/dim]",
            style="magenta", box=box.ROUNDED,
        ))
        tbl = Table(box=box.SIMPLE, header_style="bold magenta", show_lines=False)
        tbl.add_column("Domain",           style="magenta", no_wrap=True)
        tbl.add_column("Public IP",        style="dim")
        tbl.add_column("Error / scan page",style="dim red")
        tbl.add_column("Suggested action", style="magenta")
        for r in blocked_list:
            err = r.proxy_page or r.fetch_error or "-"
            tbl.add_row(
                r.hostname,
                r.dns.local_ip or r.dns.external_ip or "-",
                err,
                "Check PAC file; if DIA add --dia-domain",
            )
        console.print(tbl)
        console.print()

    ############################# Internal #
    int_list = sorted(by_routing[Routing.INTERNAL], key=lambda r: r.hostname)
    if int_list:
        console.print(Rule(style="green"))
        console.print(Panel(
            "[bold green]Internal Domains - Accessible via Jumpbox VPN[/bold green]\n"
            "Private IPs or split-horizon DNS. Route through the VPN tunnel.",
            style="green", box=box.ROUNDED,
        ))
        tbl = Table(box=box.SIMPLE, header_style="bold green", show_lines=False)
        tbl.add_column("Domain",      style="green",    no_wrap=True)
        tbl.add_column("Local IP",    style="dim green")
        tbl.add_column("External IP", style="dim")
        tbl.add_column("Note",        style="cyan")
        for r in int_list:
            if r.dns.is_private:
                note = "Private IP - internal network only"
            elif r.dns.split_horizon:
                note = "Split-horizon DNS (private local / no public record)"
            else:
                note = "Local-only DNS - not in public DNS"
            tbl.add_row(r.hostname, r.dns.local_ip or "-", r.dns.external_ip or "-", note)
        console.print(tbl)
        console.print()

    ############################# Internal + Proxy #
    int_proxy_list = sorted(by_routing[Routing.INTERNAL_PROXY], key=lambda r: r.hostname)
    if int_proxy_list:
        console.print(Rule(style="blue"))
        console.print(Panel(
            "[bold blue]Needs Corporate Proxy (via Jumpbox)[/bold blue]\n\n"
            "These domains are not directly reachable via the jumpbox — they require\n"
            "the corporate proxy. Set HTTPS_PROXY on the jumpbox, or configure Burp\n"
            "Suite with an upstream proxy rule via SOCKS5 → corporate proxy.",
            style="blue", box=box.ROUNDED,
        ))
        tbl = Table(box=box.SIMPLE, header_style="bold blue", show_lines=False)
        tbl.add_column("Domain",      style="blue",    no_wrap=True)
        tbl.add_column("IP",          style="dim blue")
        tbl.add_column("Proxy error / scan page", style="dim red")
        tbl.add_column("Action",      style="dim")
        for r in int_proxy_list:
            err = r.proxy_page or r.proxy_error or "-"
            tbl.add_row(
                r.hostname,
                r.dns.local_ip or r.dns.external_ip or "-",
                err,
                "HTTPS_PROXY on jumpbox",
            )
        console.print(tbl)
        console.print()

    ############################# External #
    ext_list = sorted(by_routing[Routing.EXTERNAL], key=lambda r: r.hostname)
    if ext_list:
        console.print(Rule(style="cyan"))
        if socks_configured:
            ext_desc = (
                "[bold cyan]External Domains - Reachable via SOCKS (Public Internet)[/bold cyan]\n"
                "Public IPs, reachable via the jumpbox. "
                "If the jumpbox needs a proxy to reach these, set HTTPS_PROXY on the jumpbox."
            )
            ext_action = "Optional: export HTTPS_PROXY=http://proxy:port on jumpbox"
        else:
            ext_desc = (
                "[bold cyan]Public Internet Domains[/bold cyan]\n"
                "Resolvable public domains. No SOCKS/jumpbox was configured — "
                "these are standard internet-facing hosts."
            )
            ext_action = "No routing action required (public internet)"
        console.print(Panel(ext_desc, style="cyan", box=box.ROUNDED))
        tbl = Table(box=box.SIMPLE, header_style="bold cyan", show_lines=False)
        tbl.add_column("Domain", style="cyan",     no_wrap=True)
        tbl.add_column("IP",     style="dim cyan")
        tbl.add_column("Action", style="dim")
        for r in ext_list:
            tbl.add_row(r.hostname, r.dns.local_ip or r.dns.external_ip or "-", ext_action)
        console.print(tbl)
        console.print()

    ############################# Unresolvable #
    dead_list = sorted(by_routing[Routing.UNRESOLVABLE], key=lambda r: r.hostname)
    if dead_list:
        console.print(Rule(style="dim"))
        console.print(Panel("[dim]Unresolvable - No DNS from either perspective[/dim]",
                            style="dim", box=box.ROUNDED))
        tbl = Table(box=box.SIMPLE, header_style="dim", show_lines=False)
        tbl.add_column("Domain", style="dim", no_wrap=True)
        for r in dead_list:
            tbl.add_row(r.hostname)
        console.print(tbl)
        console.print()

    console.print(Rule())
    console.print(
        "[bold green]■[/bold green] Internal (VPN)  "
        "[bold blue]■[/bold blue] Needs corp proxy  "
        "[bold cyan]■[/bold cyan] External (direct/proxy)  "
        "[bold yellow]■[/bold yellow] DIA → host network  "
        "[bold magenta]■[/bold magenta] SOCKS blocked (check PAC)  "
        "[dim]■[/dim] Unresolvable"
    )
    console.print()


############################# Interactive setup #############################

def _prompt_proxy_config() -> Optional[ProxyConfig]:
    """Ask all proxy-related questions and return a ProxyConfig or None."""
    has_proxy = Confirm.ask(
        "[cyan]Does the environment use a corporate proxy?[/cyan]",
        default=True,
    )
    if not has_proxy:
        return None

    proxy_url = Prompt.ask("[cyan]Proxy URL[/cyan]", default="http://proxy.corp.local:8080").strip()

    has_auth = Confirm.ask("[cyan]Does the proxy require authentication?[/cyan]", default=False)
    if not has_auth:
        has_cert = Confirm.ask("[cyan]Does the proxy use a custom TLS certificate / SSL inspection?[/cyan]", default=False)
        cert_path: Union[bool, str] = False
        if has_cert:
            cp = Prompt.ask("[cyan]Path to proxy CA certificate bundle (leave blank to skip verification)[/cyan]", default="").strip()
            cert_path = cp if cp else False
        return ProxyConfig(url=proxy_url, cert_path=cert_path)

    auth_choice = Prompt.ask(
        "[cyan]Proxy authentication type[/cyan]",
        choices=["basic", "ntlm"],
        default="basic",
    )

    username = Prompt.ask("[cyan]Proxy username[/cyan]").strip()
    password = getpass.getpass("  Proxy password: ")

    ntlm_domain: Optional[str] = None
    ntlm_dc:     Optional[str] = None

    if auth_choice == "ntlm":
        if not _HAS_NTLM:
            console.print(
                "[bold yellow]⚠  requests-ntlm is not installed. "
                "Install it with: pip install requests-ntlm[/bold yellow]"
            )
        ntlm_domain = Prompt.ask("[cyan]Windows domain name (e.g. CORP)[/cyan]").strip() or None
        ntlm_dc_raw = Prompt.ask(
            "[cyan]Domain controller hostname (optional, press Enter to skip)[/cyan]", default=""
        ).strip()
        ntlm_dc = ntlm_dc_raw or None

    has_cert = Confirm.ask("[cyan]Does the proxy use a custom TLS certificate / SSL inspection?[/cyan]", default=False)
    cert_path = False
    if has_cert:
        cp = Prompt.ask("[cyan]Path to proxy CA certificate bundle (leave blank to skip verification)[/cyan]", default="").strip()
        cert_path = cp if cp else False

    return ProxyConfig(
        url=proxy_url,
        username=username,
        password=password,
        auth_type=auth_choice,
        ntlm_domain=ntlm_domain,
        ntlm_dc=ntlm_dc,
        cert_path=cert_path,
    )


def interactive_setup(socks_port_hint: Optional[int]) -> tuple[Optional[int], str, Optional[PacResult], Optional[ProxyConfig]]:
    """Returns (socks_port, target_url, pac_result, proxy_cfg)."""
    console.print(Panel(
        "[bold blue]IsItProxy[/bold blue] - Jumpbox Routing Analyser\n\n"
        "Runs from your [bold]local machine[/bold].\n"
        "Tests each domain from three angles:\n"
        "  [green]1.[/green] Via jumpbox (SSH SOCKS)\n"
        "  [cyan]2.[/cyan] Direct internet (no proxy)\n"
        "  [blue]3.[/blue] Via corporate proxy\n\n"
        "Classifies each domain for Burp Suite routing.",
        box=box.ROUNDED, style="blue",
    ))
    console.print()

    socks_port: Optional[int] = socks_port_hint
    pac_result: Optional[PacResult] = None

    from_local = Confirm.ask(
        "[cyan]Are you running this from an off-network machine?[/cyan]",
        default=True,
    )

    if from_local:
        console.print()
        console.print("[dim]To create a SOCKS proxy in a separate terminal:[/dim]")
        console.print("  [bold green]ssh -D 1080 -N -q user@jumpbox[/bold green]")
        console.print()

        has_socks = Confirm.ask("[cyan]Do you have an SSH SOCKS proxy running?[/cyan]", default=True)

        if has_socks:
            if socks_port is None:
                port_str = Prompt.ask("[cyan]SOCKS proxy port[/cyan]", default="1080")
                try:
                    socks_port = int(port_str)
                except ValueError:
                    console.print("[yellow]Invalid port - continuing without SOCKS proxy.[/yellow]")
                    socks_port = None

            if socks_port:
                with console.status(f"[blue]Testing SOCKS5 on 127.0.0.1:{socks_port}…[/blue]"):
                    ok = _test_socks(socks_port)
                if ok:
                    console.print(f"[bold green]✓ SOCKS proxy on port {socks_port} is responding.[/bold green]")
                else:
                    console.print(f"[bold yellow]⚠  SOCKS proxy on port {socks_port} did not respond.[/bold yellow]")
                    console.print("[dim]  Is 'ssh -D 1080 -N user@jumpbox' running?[/dim]")
                    if not Confirm.ask("[cyan]Continue anyway?[/cyan]", default=False):
                        sys.exit(0)
        else:
            console.print("[yellow]No SOCKS proxy - jumpbox perspective unavailable.[/yellow]")
    else:
        console.print("[yellow]Running without SOCKS proxy. DNS reflects your machine's resolvers.[/yellow]")

    # PAC file — always offered regardless of network mode
    console.print()
    has_pac = Confirm.ask(
        "[cyan]Do you have access to a PAC file? (local path or URL)[/cyan]",
        default=False,
    )
    if has_pac:
        pac_source = Prompt.ask("[cyan]PAC file path or URL[/cyan]").strip()
        pac_result = _try_load_pac(pac_source, socks_port)

    # Proxy config — always offered
    console.print()
    proxy_cfg = _prompt_proxy_config()

    console.print()
    target = Prompt.ask("[cyan]Target URL or hostname[/cyan]").strip()

    return socks_port, target, pac_result, proxy_cfg


def _try_load_pac(source: str, socks_port: Optional[int]) -> Optional[PacResult]:
    try:
        with console.status(f"[blue]Loading PAC file from {source}…[/blue]"):
            content = load_pac(source, socks_port)
        pac = parse_pac_content(content, source)
        print_pac_summary(pac)
        return pac
    except Exception as exc:
        console.print(f"[bold red]Failed to load PAC file:[/bold red] {exc}")
        return None


def _test_socks(port: int) -> bool:
    try:
        s = requests.Session()
        s.proxies = {"http": f"socks5h://127.0.0.1:{port}",
                     "https": f"socks5h://127.0.0.1:{port}"}
        s.get("http://www.msftconnecttest.com/connecttest.txt", timeout=6, verify=False)
        return True
    except Exception:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3):
                return True
        except OSError:
            return False


############################# Session builder ##############################

def _make_session(socks_port: Optional[int] = None) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = _UA
    if socks_port:
        s.proxies = {
            "http":  f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }
    return s


############################# Burp Suite config generator ########################

def generate_burp_config(
    all_results: dict[str, DomainResult],
    socks_port:  Optional[int],
    target_hostname: str,
) -> Path:
    """
    Write a Burp Suite project-options JSON that routes traffic correctly
    without needing a proxy configured on the jumpbox:

    • INTERNAL domains  → upstream SOCKS5 rule pointing at the SSH tunnel
                          (127.0.0.1:<socks_port>) so Burp reaches them via
                          the jumpbox exactly as the jumpbox would.
    • DIA / EXTERNAL    → NO rule, so Burp connects directly from the
                          pentester's machine (bypasses the jumpbox entirely).

    Import in Burp Suite:
      Project options > Misc > Save/restore > Restore project options
      - or -
      Settings (gear icon) > Project > Load project options file
    """
    socks_port = socks_port or 1080
    servers: list[dict] = []

    internal = sorted(
        (r for r in all_results.values() if r.routing == Routing.INTERNAL),
        key=lambda r: r.hostname,
    )

    for r in internal:
        for pattern in (r.hostname, f"*.{r.hostname}"):
            servers.append({
                "authentication": {
                    "password": "",
                    "type":     "none",
                    "username": "",
                },
                "destination_host": pattern,
                "enabled":          True,
                "proxy_host":       "127.0.0.1",
                "proxy_port":       socks_port,
                "proxy_type":       "SOCKS5",
            })

    # DIA and EXTERNAL domains intentionally have no rule - Burp connects
    # to them directly from the pentester's machine.

    config = {
        "project_options": {
            "connections": {
                "upstream_proxy": {
                    "servers":           servers,
                    "use_upstream_proxy": bool(servers),
                }
            }
        }
    }

    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path(f"IsItProxy_burp_{target_hostname}_{ts}.json")
    path.write_text(json.dumps(config, indent=2))
    return path


def print_burp_summary(
    path:        Path,
    all_results: dict[str, DomainResult],
    socks_port:  int,
) -> None:
    by_routing: dict[Routing, list[DomainResult]] = {r: [] for r in Routing}
    for r in all_results.values():
        by_routing[r.routing].append(r)

    internal_count = len(by_routing[Routing.INTERNAL])
    dia_count      = len(by_routing[Routing.DIA_REQUIRED])
    ext_count      = len(by_routing[Routing.EXTERNAL])
    blocked_count  = len(by_routing[Routing.SOCKS_BLOCKED])

    console.print(Rule(style="blue"))
    console.print(Panel(
        f"[bold white]Burp Suite Config Generated[/bold white]\n\n"
        f"[dim]File:[/dim] [bold cyan]{path}[/bold cyan]\n\n"
        f"[bold]Rules written:[/bold]\n"
        f"  [green]{internal_count * 2}[/green] upstream SOCKS5 rules "
        f"([green]{internal_count}[/green] internal domains × exact + wildcard)\n"
        f"  [yellow]{dia_count}[/yellow] DIA domains - [bold]no rule[/bold] (Burp connects direct)\n"
        f"  [cyan]{ext_count}[/cyan] external domains - [bold]no rule[/bold] (Burp connects direct)\n"
        + (f"  [magenta]{blocked_count}[/magenta] SOCKS-blocked - [bold]no rule[/bold] (investigate PAC)\n" if blocked_count else "")
        + f"\n[bold]How to import:[/bold]\n"
        f"  Burp Suite → [italic]Project options[/italic] → [italic]Misc[/italic] → "
        f"[italic]Save/restore[/italic] → [bold]Restore project options[/bold]\n"
        f"  (Burp 2023+: gear icon → [italic]Project[/italic] → [bold]Load project options file[/bold])\n\n"
        f"[bold yellow]Important:[/bold yellow] Do [bold]NOT[/bold] enable a global SOCKS proxy in Burp.\n"
        f"The upstream rules handle internal routing via SOCKS5 127.0.0.1:{socks_port}.\n"
        f"DIA and external traffic goes direct from your machine automatically.",
        box=box.ROUNDED,
        style="blue",
    ))
    console.print()


############################# Entry point ################################

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog="IsItProxy",
        description="Jumpbox domain routing analyser for pentest engagements.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive (recommended)
  python IsItProxy.py

  # Non-interactive with SOCKS + PAC file
  python IsItProxy.py --url https://portal.corp.local --socks-port 1080 \\
      --pac-file /path/to/proxy.pac

  # With authenticated proxy (Basic)
  python IsItProxy.py --url https://portal.corp.local --socks-port 1080 \\
      --proxy http://proxy.corp.local:8080 --proxy-user jsmith \\
      --proxy-pass secret --proxy-auth basic

  # With authenticated proxy (NTLM)
  python IsItProxy.py --url https://portal.corp.local --socks-port 1080 \\
      --proxy http://proxy.corp.local:8080 --proxy-user jsmith \\
      --proxy-pass secret --proxy-auth ntlm --proxy-domain CORP \\
      --proxy-dc dc01.corp.local

  # With proxy SSL inspection CA cert
  python IsItProxy.py --url https://portal.corp.local --socks-port 1080 \\
      --proxy http://proxy.corp.local:8080 --proxy-cert /path/to/ca-bundle.pem

  # No SOCKS, no PAC, DNS-only
  python IsItProxy.py --url portal.corp.local --no-socks --depth 0
        """,
    )
    parser.add_argument("--url",        help="Target URL or hostname")
    parser.add_argument("--socks-port", type=int, metavar="PORT",
                        help="SOCKS5 proxy port on 127.0.0.1")
    parser.add_argument("--no-socks",  action="store_true",
                        help="Skip SOCKS proxy, use local DNS only")
    parser.add_argument("--pac-file",  metavar="FILE",
                        help="Local PAC file to parse for DIA domains")
    parser.add_argument("--pac-url",   metavar="URL",
                        help="URL of PAC file to fetch and parse")
    parser.add_argument("--no-builtin-dia", action="store_true",
                        help="Do not include built-in Microsoft DIA domains (use PAC/custom only)")
    parser.add_argument("--dia-domain", action="append", default=[], metavar="DOMAIN",
                        help="Additional DIA apex domain (repeatable)")
    parser.add_argument("--dia-file",  type=Path, metavar="FILE",
                        help="File of DIA apex domains, one per line (# = comment)")
    parser.add_argument("--depth",     type=int, default=2, metavar="N",
                        help="Crawl depth (default: 2; 0 = DNS + NS only)")
    parser.add_argument("--timeout",   type=int, default=10, metavar="SEC",
                        help="Per-request HTTP timeout (default: 10)")
    # Proxy auth arguments
    parser.add_argument("--proxy",      metavar="URL",
                        help="Corporate proxy URL (e.g. http://proxy.corp.local:8080)")
    parser.add_argument("--proxy-user", metavar="USER",  help="Proxy username")
    parser.add_argument("--proxy-pass", metavar="PASS",  help="Proxy password")
    parser.add_argument("--proxy-auth", metavar="TYPE",  choices=["none", "basic", "ntlm"],
                        default="none", help="Proxy auth type: none, basic, ntlm (default: none)")
    parser.add_argument("--proxy-domain", metavar="DOMAIN",
                        help="Windows domain for NTLM proxy auth (e.g. CORP)")
    parser.add_argument("--proxy-dc",   metavar="HOST",
                        help="Domain controller hostname for NTLM proxy auth (optional)")
    parser.add_argument("--proxy-cert", metavar="FILE",
                        help="CA certificate bundle for proxy TLS verification")
    args = parser.parse_args()

    # Determine mode
    pac_source     = args.pac_file or args.pac_url
    fully_scripted = args.url is not None and (args.socks_port is not None or args.no_socks)

    pac_result: Optional[PacResult]  = None
    proxy_cfg:  Optional[ProxyConfig] = None

    if fully_scripted:
        target     = args.url
        socks_port = None if args.no_socks else args.socks_port
        if pac_source:
            pac_result = _try_load_pac(pac_source, socks_port)
        if args.proxy:
            proxy_cfg = ProxyConfig(
                url         = args.proxy,
                username    = args.proxy_user,
                password    = args.proxy_pass,
                auth_type   = args.proxy_auth,
                ntlm_domain = args.proxy_domain,
                ntlm_dc     = args.proxy_dc,
                cert_path   = args.proxy_cert or False,
            )
    else:
        socks_port, target, pac_result, proxy_cfg = interactive_setup(
            socks_port_hint=args.socks_port if not args.no_socks else None,
        )
        if args.url:
            target = args.url
        if pac_source and pac_result is None:
            pac_result = _try_load_pac(pac_source, socks_port)
        # CLI proxy args override interactive proxy config
        if args.proxy:
            proxy_cfg = ProxyConfig(
                url         = args.proxy,
                username    = args.proxy_user,
                password    = args.proxy_pass,
                auth_type   = args.proxy_auth,
                ntlm_domain = args.proxy_domain,
                ntlm_dc     = args.proxy_dc,
                cert_path   = args.proxy_cert or False,
            )

    # Build DIA set
    dia_set = build_dia_set(
        extra_domains   = args.dia_domain,
        dia_file        = args.dia_file,
        pac_result      = pac_result,
        include_builtin = not args.no_builtin_dia,
    )

    # Normalise URL
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    hostname = urlparse(target).hostname
    if not hostname:
        console.print("[bold red]Error:[/bold red] Cannot extract hostname from URL.")
        sys.exit(1)

    session = _make_session(socks_port)

    proxy_label = "none"
    if proxy_cfg:
        auth_label  = f" [{proxy_cfg.auth_type}]" if proxy_cfg.auth_type != "none" else ""
        proxy_label = f"{proxy_cfg.url}{auth_label}"

    console.print(
        f"\n[bold blue]Analysing[/bold blue]  [cyan]{hostname}[/cyan]  "
        f"depth=[cyan]{args.depth}[/cyan]  "
        f"socks=[cyan]{'127.0.0.1:' + str(socks_port) if socks_port else 'none'}[/cyan]  "
        f"corp-proxy=[cyan]{proxy_label}[/cyan]  "
        f"DIA domains=[cyan]{len(dia_set)}[/cyan]"
    )

    visited: set[str] = set()
    with console.status(f"[bold blue]Crawling {hostname}…[/bold blue]", spinner="dots"):
        root = analyse(
            hostname,
            0,
            args.depth,
            visited,
            session if socks_port else None,
            args.timeout,
            dia_set,
            fetch_ns=True,
            proxy_cfg=proxy_cfg,
        )

    print_results(root, target, socks_port, dia_set, pac_result, proxy_cfg, socks_configured=bool(socks_port))

    # Generate Burp Suite upstream proxy config
    all_r: dict[str, DomainResult] = {}
    _collect_all(root, all_r)
    if any(r.routing == Routing.INTERNAL for r in all_r.values()):
        burp_path = generate_burp_config(all_r, socks_port, hostname)
        print_burp_summary(burp_path, all_r, socks_port or 1080)
    else:
        console.print("[dim]No internal domains found - Burp config not written.[/dim]\n")


if __name__ == "__main__":
    main()
