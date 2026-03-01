# 🛡️ ShieldScan

A security scanner with a web dashboard. Check any website or server for open services, known vulnerabilities (via NIST NVD), and capture live screenshots.

## Quick Start

```bash
pip install -r requirements.txt
playwright install chromium
python dashboard.py
```

Open **http://localhost:5000**

## Project Structure

```
scanner.py      ← Core engine (scanning, CVE lookup via dynamic CPE, screenshots)
dashboard.py    ← Web server (Flask + SocketIO, imports from scanner.py)
templates/      ← HTML
static/         ← CSS + JS
Dockerfile      ← For deployment
```

## Deploy

### Railway (Easiest)
```bash
# Install Railway CLI
npm i -g @railway/cli
railway login
railway init
railway up
```

### Docker (Any VPS)
```bash
docker build -t shieldscan .
docker run -p 5000:5000 shieldscan
```

### Render
1. Push to GitHub
2. Go to render.com → New Web Service
3. Connect your repo
4. Build Command: `pip install -r requirements.txt && playwright install --with-deps chromium`
5. Start Command: `python dashboard.py`
