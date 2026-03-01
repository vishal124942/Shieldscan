
import asyncio
import socket
import re
from typing import List, Dict, Any
import aiohttp
from playwright.async_api import async_playwright

# ─────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────

def parse_ports(port_string: str) -> List[int]:
    """Parse '80,443' or '1-100' or '22,80,100-200' into a sorted list."""
    ports = set()
    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = map(int, part.split("-", 1))
                if 1 <= start <= end <= 65535:
                    ports.update(range(start, end + 1))
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                pass
    return sorted(ports)


def get_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def is_ip(target: str) -> bool:
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False


# ─────────────────────────────────────────────────────────
# Subdomain Enumeration
# ─────────────────────────────────────────────────────────

async def enumerate_subdomains(domain: str) -> List[str]:
    """Discover subdomains via the crt.sh certificate transparency database."""
    if is_ip(domain):
        return [domain]

    subdomains = {domain}
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    for entry in await resp.json():
                        name = entry.get("name_value", "").lower()
                        if not name.startswith("*"):
                            subdomains.update(name.split("\n"))
    except Exception:
        pass
    return sorted(subdomains)


# ─────────────────────────────────────────────────────────
# Banner Grabbing (Dynamic HTTP Detection)
# ─────────────────────────────────────────────────────────

def _extract_server_header(http_response: str) -> str:
    """Pull 'Server: ...' header from raw HTTP response."""
    for line in http_response.split("\n"):
        if line.lower().startswith("server:"):
            return line.strip()
    return http_response.split("\n")[0][:100]


async def grab_banner(reader, writer, target: str, port: int) -> Dict[str, Any]:
    """
    Dynamically detect what's running on any port:
      1. Listen first — catches SSH, FTP, SMTP (services that talk first)
      2. If silent, probe with HTTP HEAD — detects web servers on any port
    """
    banner, is_http = "", False

    try:
        # Step 1: Listen for a banner (1.5s)
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            if data:
                raw = data.decode("utf-8", errors="ignore").strip()
                if raw.startswith("HTTP/"):
                    is_http = True
                    banner = _extract_server_header(raw)
                else:
                    return {"banner": raw.split("\n")[0][:100], "is_http": False}
        except asyncio.TimeoutError:
            pass

        # Step 2: Server was silent — probe with HTTP
        if not banner:
            try:
                writer.write(f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode())
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                if data:
                    raw = data.decode("utf-8", errors="ignore").strip()
                    if "HTTP/" in raw:
                        is_http = True
                        banner = _extract_server_header(raw)
                    else:
                        banner = raw.split("\n")[0][:100]
            except Exception:
                pass
    except Exception:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    return {"banner": banner, "is_http": is_http}


# ─────────────────────────────────────────────────────────
# Port Scanning
# ─────────────────────────────────────────────────────────

async def scan_port(target: str, port: int, timeout: float, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
    """Scan a single port and grab its banner."""
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=timeout
            )
            result = await grab_banner(reader, writer, target, port)
            return {
                "host": target, "port": port, "state": "open",
                "service": get_service_name(port),
                "banner": result["banner"], "is_http": result["is_http"],
                "cves": []
            }
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return {"host": target, "port": port, "state": "closed"}


# ─────────────────────────────────────────────────────────
# CVE Lookup — Dynamic CPE Resolution via NVD API
# ─────────────────────────────────────────────────────────
# Professional approach (like Nessus/Qualys):
#   1. Extract product + version from banner (one generic regex)
#   2. Query NVD CPE Dictionary API to find the official CPE
#   3. Query NVD CVE API using that exact CPE
# Zero hardcoded product mappings.

def _extract_product_version(banner: str) -> tuple[str, str] | None:
    """
    Extract product name and version from any banner.
    One regex handles all formats: Apache/2.4.7, OpenSSH_8.2p1, nginx 1.18.0
    """
    cleaned = banner.replace("Server:", "").strip()
    match = re.search(r'([A-Za-z][\w.-]+)[/_\s-](\d+\.\d+(?:\.\d+)*)', cleaned)
    if match:
        return match.group(1).rstrip("-_"), match.group(2)
    return None


async def _resolve_cpe(product: str, version: str) -> str | None:
    """Query the NVD CPE Dictionary API to find the official CPE for a product."""
    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    params = {"keywordSearch": f"{product} {version}", "resultsPerPage": 1}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    products = data.get("products", [])
                    if products:
                        return products[0].get("cpe", {}).get("cpeName")
    except Exception:
        pass
    return None


async def check_cves(banner: str) -> List[Dict]:
    """
    Full CVE lookup pipeline:
      Banner → extract product/version → resolve CPE → query CVEs
    """
    if not banner:
        return []

    extracted = _extract_product_version(banner)
    if not extracted:
        return []

    product, version = extracted
    cpe = await _resolve_cpe(product, version)
    if not cpe:
        return []

    cves = []
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cpeName": cpe, "resultsPerPage": 5}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    for vuln in (await resp.json()).get("vulnerabilities", []):
                        cve = vuln.get("cve", {})
                        score, severity = 0, "N/A"
                        cvss = cve.get("metrics", {}).get("cvssMetricV31", []) or cve.get("metrics", {}).get("cvssMetricV30", [])
                        if cvss:
                            score = cvss[0].get("cvssData", {}).get("baseScore", 0)
                            severity = cvss[0].get("cvssData", {}).get("baseSeverity", "N/A")

                        desc = next(
                            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                            "No description available."
                        )
                        # Only report HIGH (7.0+) and CRITICAL vulnerabilities
                        if score >= 7.0:
                            cves.append({
                                "id": cve.get("id", "?"), "score": score,
                                "severity": severity, "description": desc, "cpe": cpe,
                                "solution": f"Update {product} to the latest stable version.",
                                "link": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '?')}"
                            })
    except Exception:
        pass
    return cves



# ─────────────────────────────────────────────────────────
# HTTP Security Header Analysis
# ─────────────────────────────────────────────────────────

SECURITY_HEADERS = [
    {
        "header": "Strict-Transport-Security",
        "severity": "HIGH",
        "missing_desc": "No HTTPS enforcement — traffic can be intercepted by attackers on public Wi-Fi.",
        "fix": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    {
        "header": "Content-Security-Policy",
        "severity": "HIGH",
        "missing_desc": "No XSS protection — attackers can inject malicious scripts into your pages.",
        "fix": "Add header: Content-Security-Policy: default-src 'self'; script-src 'self'"
    },
    {
        "header": "X-Frame-Options",
        "severity": "MEDIUM",
        "missing_desc": "Clickjacking possible — your site can be embedded in a hidden iframe to trick users.",
        "fix": "Add header: X-Frame-Options: DENY"
    },
    {
        "header": "X-Content-Type-Options",
        "severity": "MEDIUM",
        "missing_desc": "MIME sniffing allowed — browsers may misinterpret files, enabling attacks.",
        "fix": "Add header: X-Content-Type-Options: nosniff"
    },
    {
        "header": "Referrer-Policy",
        "severity": "LOW",
        "missing_desc": "Full URL leaked to third-party sites when users click links, exposing private paths.",
        "fix": "Add header: Referrer-Policy: strict-origin-when-cross-origin"
    },
    {
        "header": "Permissions-Policy",
        "severity": "LOW",
        "missing_desc": "No restrictions on browser features — scripts can access camera, microphone, geolocation.",
        "fix": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    },
]


async def check_security_headers(url: str) -> Dict[str, Any]:
    """
    Analyze HTTP response headers for security best practices.
    Returns a grade (A-F) and a list of missing/present headers.
    """
    findings = []
    passed = 0
    total = len(SECURITY_HEADERS)
    raw_headers = {}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8),
                                   allow_redirects=True, ssl=False) as resp:
                raw_headers = dict(resp.headers)

                for check in SECURITY_HEADERS:
                    header_val = resp.headers.get(check["header"])
                    if header_val:
                        passed += 1
                        findings.append({
                            "header": check["header"],
                            "status": "present",
                            "value": header_val[:100],
                            "severity": check["severity"],
                        })
                    else:
                        findings.append({
                            "header": check["header"],
                            "status": "missing",
                            "severity": check["severity"],
                            "description": check["missing_desc"],
                            "fix": check["fix"],
                        })

                # Check for risky headers that SHOULD be hidden
                server_val = resp.headers.get("Server", "")
                if server_val and any(c.isdigit() for c in server_val):
                    findings.append({
                        "header": "Server",
                        "status": "warning",
                        "severity": "MEDIUM",
                        "value": server_val,
                        "description": f"Server version exposed: '{server_val}' — helps attackers pick the right exploit.",
                        "fix": "Hide version info. Nginx: server_tokens off; Apache: ServerTokens Prod",
                    })

    except Exception:
        return {"url": url, "grade": "?", "findings": [], "passed": 0, "total": total}

    # Calculate grade
    ratio = passed / total if total else 0
    if ratio >= 0.9:
        grade = "A"
    elif ratio >= 0.7:
        grade = "B"
    elif ratio >= 0.5:
        grade = "C"
    elif ratio >= 0.3:
        grade = "D"
    else:
        grade = "F"

    return {
        "url": url, "grade": grade, "findings": findings,
        "passed": passed, "total": total,
    }


# ─────────────────────────────────────────────────────────
# Route / Directory Discovery (Dynamic)
# ─────────────────────────────────────────────────────────
# Instead of brute-forcing a hardcoded wordlist, we discover routes
# from the website itself:
#   1. Parse robots.txt — sites list hidden paths here
#   2. Parse sitemap.xml — lists every page
#   3. Crawl homepage HTML — extract all <a href> links
#   4. Probe a small list of known sensitive files (/.env, /.git, etc.)

from urllib.parse import urlparse, urljoin

# Only these are hardcoded — known dangerous files that should NEVER be public
SENSITIVE_PROBES = [
    "/.env", "/.git", "/.git/config", "/.htaccess", "/wp-config.php.bak",
    "/server-status", "/server-info", "/debug", "/console", "/phpmyadmin",
    "/backup", "/.aws/credentials", "/.DS_Store",
]


async def _fetch_text(session, url: str, timeout: float = 5) -> str:
    """Fetch a URL and return text, or empty string on failure."""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                               allow_redirects=True, ssl=False) as resp:
            if resp.status == 200:
                return await resp.text()
    except Exception:
        pass
    return ""


async def _paths_from_robots(session, base_url: str) -> List[str]:
    """Extract Disallow and Allow paths from robots.txt."""
    text = await _fetch_text(session, f"{base_url}/robots.txt")
    paths = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("Disallow:", "Allow:")):
            path = line.split(":", 1)[1].strip()
            if path and path != "/" and "*" not in path:
                paths.append(path)
    return paths


async def _paths_from_sitemap(session, base_url: str) -> List[str]:
    """Extract URLs from sitemap.xml."""
    text = await _fetch_text(session, f"{base_url}/sitemap.xml")
    paths = []
    for match in re.finditer(r'<loc>(.*?)</loc>', text):
        full_url = match.group(1)
        parsed = urlparse(full_url)
        if parsed.path and parsed.path != "/":
            paths.append(parsed.path)
    return paths[:50]  # Cap to avoid huge sitemaps


async def _paths_from_crawl(session, base_url: str) -> List[str]:
    """Crawl homepage HTML and extract all <a href> links."""
    text = await _fetch_text(session, base_url)
    paths = set()
    base_parsed = urlparse(base_url)

    for match in re.finditer(r'href=["\']([^"\']+)["\']', text, re.IGNORECASE):
        href = match.group(1)

        # Skip external links, anchors, javascript, mailto
        if href.startswith(("http://", "https://")):
            parsed = urlparse(href)
            if parsed.hostname and parsed.hostname != base_parsed.hostname:
                continue
            href = parsed.path
        elif href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue

        if href and href != "/" and not href.startswith("//"):
            paths.add(href.split("?")[0].split("#")[0])  # Strip query/fragment

    return list(paths)[:50]


async def _probe_path(session, base_url: str, path: str) -> Dict | None:
    """Check if a path exists and return its info."""
    try:
        full_url = f"{base_url.rstrip('/')}{path}" if path.startswith("/") else urljoin(base_url, path)
        async with session.get(full_url, timeout=aiohttp.ClientTimeout(total=5),
                               allow_redirects=False, ssl=False) as resp:
            if resp.status in (200, 301, 302, 403):
                is_sensitive = path in SENSITIVE_PROBES
                risk = "danger" if is_sensitive and resp.status == 200 else \
                       "warning" if resp.status == 403 else "info"

                return {
                    "path": path,
                    "status": resp.status,
                    "size": resp.headers.get("Content-Length", "?"),
                    "risk": risk,
                    "source": "sensitive_probe" if is_sensitive else "discovered",
                    "redirect": resp.headers.get("Location", "") if resp.status in (301, 302) else "",
                }
    except Exception:
        pass
    return None


async def discover_routes(url: str) -> Dict[str, Any]:
    """
    Dynamic route discovery pipeline:
      1. robots.txt  → extract disallowed paths
      2. sitemap.xml → extract all listed pages
      3. Homepage    → crawl <a href> links
      4. Sensitive    → probe known dangerous files
    """
    all_paths = set()
    sources = {"robots": 0, "sitemap": 0, "crawl": 0, "sensitive": len(SENSITIVE_PROBES)}

    try:
        async with aiohttp.ClientSession() as session:
            # Step 1: robots.txt
            robot_paths = await _paths_from_robots(session, url)
            sources["robots"] = len(robot_paths)
            all_paths.update(robot_paths)

            # Step 2: sitemap.xml
            sitemap_paths = await _paths_from_sitemap(session, url)
            sources["sitemap"] = len(sitemap_paths)
            all_paths.update(sitemap_paths)

            # Step 3: Crawl homepage
            crawl_paths = await _paths_from_crawl(session, url)
            sources["crawl"] = len(crawl_paths)
            all_paths.update(crawl_paths)

            # Step 4: Always probe sensitive files
            all_paths.update(SENSITIVE_PROBES)

            # Probe all discovered paths
            found = []
            for path in sorted(all_paths):
                result = await _probe_path(session, url, path)
                if result:
                    found.append(result)

    except Exception:
        found = []

    return {
        "url": url,
        "routes": found,
        "total_checked": len(all_paths),
        "sources": sources,
    }


# ─────────────────────────────────────────────────────────
# Screenshots
# ─────────────────────────────────────────────────────────

async def take_screenshot(url: str, filepath: str) -> bool:
    """Capture a headless browser screenshot of any web interface."""
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page(ignore_https_errors=True)
            await page.set_viewport_size({"width": 1280, "height": 720})
            await page.goto(url, timeout=15000, wait_until="networkidle")
            await page.screenshot(path=filepath)
            await browser.close()
            return True
    except Exception:
        return False
