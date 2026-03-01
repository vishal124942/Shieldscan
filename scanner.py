#!/usr/bin/env python3
"""
scanner.py — Core Scanning Engine
==================================
All reusable logic lives here. Both the CLI and web dashboard import from this module.

Capabilities:
  - Async port scanning with dynamic banner grabbing
  - Subdomain enumeration via crt.sh
  - Real CVE lookups via NVD API (dynamic CPE resolution, zero hardcoding)
  - Headless browser screenshots via Playwright
"""

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
                            (d["value"][:120] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                            ""
                        )
                        cves.append({
                            "id": cve.get("id", "?"), "score": score,
                            "severity": severity, "description": desc, "cpe": cpe
                        })
    except Exception:
        pass
    return cves


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
