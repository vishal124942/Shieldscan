#!/usr/bin/env python3


import asyncio
import os
import threading

import nest_asyncio
from flask import Flask, render_template, send_from_directory, request
from flask_socketio import SocketIO, emit

from scanner import (
    parse_ports, is_ip, enumerate_subdomains,
    scan_port, check_cves, check_security_headers, discover_routes, take_screenshot
)

nest_asyncio.apply()

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "portscan-secret"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

SCREENSHOTS_DIR = os.path.join(os.path.dirname(__file__), "screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

cancel_event = threading.Event()


# ─────────────────────────────────────────────────────────
# Scan Orchestrator
# ─────────────────────────────────────────────────────────

async def run_scan(target_domain, ports, concurrency, timeout):
    """Run the full scan pipeline and emit events to the browser."""

    # Clean up old screenshots to prevent disk buildup on Render
    for f in os.listdir(SCREENSHOTS_DIR):
        if f.endswith(".png"):
            try:
                os.remove(os.path.join(SCREENSHOTS_DIR, f))
            except OSError:
                pass

    def stopped():
        return cancel_event.is_set()

    socketio.emit("scan_status", {"status": "Resolving target..."})

    # 1. Subdomain Enumeration
    targets = [target_domain]
    if not is_ip(target_domain):
        socketio.emit("scan_status", {"status": "Enumerating subdomains..."})
        targets = await enumerate_subdomains(target_domain)

    socketio.emit("subdomains", {"subdomains": targets, "count": len(targets)})
    if len(targets) > 15:
        targets = targets[:15]

    # 2. Port Scanning
    semaphore = asyncio.Semaphore(concurrency)
    total = len(targets) * len(ports)
    completed = 0

    socketio.emit("scan_status", {"status": f"Scanning {total} port combinations..."})
    socketio.emit("scan_progress", {"completed": 0, "total": total})

    all_open = []
    http_services = []

    tasks = [scan_port(host, port, timeout, semaphore) for host in targets for port in ports]

    for future in asyncio.as_completed(tasks):
        if stopped():
            socketio.emit("scan_stopped", {"reason": "Cancelled by user"})
            return
        result = await future
        completed += 1

        if completed % max(1, total // 50) == 0 or completed == total:
            socketio.emit("scan_progress", {"completed": completed, "total": total})

        if result["state"] == "open":
            all_open.append(result)
            socketio.emit("port_found", {
                "host": result["host"], "port": result["port"],
                "service": result["service"], "banner": result["banner"],
                "is_http": result["is_http"]
            })
            if result["is_http"]:
                proto = "https" if result["port"] == 443 or "ssl" in result["service"] else "http"
                http_services.append(f"{proto}://{result['host']}:{result['port']}")

    # 3. CVE Lookups
    if stopped(): socketio.emit("scan_stopped", {"reason": "Cancelled by user"}); return
    socketio.emit("scan_status", {"status": "Checking CVE database..."})
    for result in all_open:
        if result["banner"]:
            cves = await check_cves(result["banner"])
            result["cves"] = cves
            if cves:
                socketio.emit("cve_found", {
                    "host": result["host"], "port": result["port"],
                    "banner": result["banner"], "cves": cves
                })
            await asyncio.sleep(0.5)  # NVD rate limit

    # 3.5 Security Header Analysis
    if stopped(): socketio.emit("scan_stopped", {"reason": "Cancelled by user"}); return
    header_results = []
    if http_services:
        socketio.emit("scan_status", {"status": f"Analyzing security headers on {len(http_services)} web services..."})
        for url in http_services:
            report = await check_security_headers(url)
            header_results.append(report)
            socketio.emit("header_report", report)

    # 3.7 Route Discovery
    if stopped(): socketio.emit("scan_stopped", {"reason": "Cancelled by user"}); return
    if http_services:
        socketio.emit("scan_status", {"status": f"Discovering routes on {len(http_services)} web services..."})
        for url in http_services:
            routes = await discover_routes(url)
            if routes["routes"]:
                socketio.emit("routes_found", routes)

    # 4. Screenshots
    if stopped(): socketio.emit("scan_stopped", {"reason": "Cancelled by user"}); return
    screenshots = []
    if http_services:
        socketio.emit("scan_status", {"status": f"Screenshotting {len(http_services)} web services..."})
        for url in http_services:
            safe = url.replace("://", "_").replace(":", "_").replace("/", "")
            filename = f"{safe}.png"
            if await take_screenshot(url, os.path.join(SCREENSHOTS_DIR, filename)):
                screenshots.append({"url": url, "filename": filename})
                socketio.emit("screenshot_taken", {"url": url, "filename": filename})

    # 5. Done
    socketio.emit("scan_complete", {
        "total_open": len(all_open),
        "total_cves": sum(len(r["cves"]) for r in all_open),
        "screenshots": screenshots,
        "results": [{
            "host": r["host"], "port": r["port"], "service": r["service"],
            "banner": r["banner"], "is_http": r["is_http"], "cves": r["cves"]
        } for r in all_open]
    })


def _run_in_thread(target, ports, concurrency, timeout):
    cancel_event.clear()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(run_scan(target, ports, concurrency, timeout))
    loop.close()


# ─────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────

@app.route("/")
def index():
    # Detect client IP. Vercel/Render use X-Forwarded-For
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip and "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()
    return render_template("index.html", client_ip=client_ip)


@app.route("/screenshots/<path:filename>")
def serve_screenshot(filename):
    return send_from_directory(SCREENSHOTS_DIR, filename)


# ─────────────────────────────────────────────────────────
# SocketIO Events
# ─────────────────────────────────────────────────────────

@socketio.on("stop_scan")
def handle_stop_scan():
    cancel_event.set()


@socketio.on("start_scan")
def handle_start_scan(data):
    target = data.get("target", "").strip()
    port_str = data.get("ports", "21,22,80,443,3000,5000,8000,8080,8443,9090")
    mode = data.get("mode", "quick")

    # Auto-tune: Deep scans need lower concurrency to avoid firewall blocks
    SCAN_PROFILES = {
        "quick": {"concurrency": 500, "timeout": 1.5},
        "full":  {"concurrency": 400, "timeout": 2.0},
        "deep":  {"concurrency": 200, "timeout": 2.5},
    }
    profile = SCAN_PROFILES.get(mode, SCAN_PROFILES["quick"])
    concurrency = profile["concurrency"]
    timeout = profile["timeout"]

    if not target:
        emit("scan_error", {"error": "No target specified"})
        return

    try:
        ports = parse_ports(port_str)
    except Exception as e:
        emit("scan_error", {"error": f"Invalid ports: {e}"})
        return

    emit("scan_started", {"target": target, "port_count": len(ports)})
    threading.Thread(target=_run_in_thread, args=(target, ports, concurrency, timeout), daemon=True).start()


# ─────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  🛡️  ShieldScan — Security Scanner")
    print("  → Open http://localhost:5000\n")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
