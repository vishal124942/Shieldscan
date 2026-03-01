/**
 * app.js — Client-side logic for the AI+Sec Scanner Dashboard
 *
 * Connects to the Flask-SocketIO backend via WebSocket and
 * updates the UI in real-time as scan results stream in.
 */

const socket = io();

// State
let openPortCount = 0;
let cveCount = 0;
let screenshotCount = 0;
let scanning = false;

// Port presets for each scan mode
const SCAN_MODES = {
    quick: "21,22,23,25,53,80,110,443,993,3000,3306,5000,5900,8000,8080,8443,8888,9090",
    full: "20,21,22,23,25,53,67,68,69,80,110,111,119,123,135,137,138,139,143,161,162,179,389,443,445,465,500,514,520,587,631,636,873,993,995,1080,1433,1434,1521,1723,2049,2082,2083,2086,2087,2095,2096,3000,3306,3389,4443,4567,5000,5432,5900,5901,6379,6667,8000,8008,8080,8443,8888,9000,9090,9200,9300,10000,11211,27017,28017",
    deep: "1-1000"
};

// ─────────────────────────────────────────────
// Scan Mode Selection
// ─────────────────────────────────────────────

function selectMode(el) {
    document.querySelectorAll('.mode-card').forEach(c => c.classList.remove('active'));
    el.classList.add('active');

    const mode = el.dataset.mode;
    document.getElementById('ports').value = SCAN_MODES[mode];
}

function setTarget(value) {
    document.getElementById('target').value = value;
    document.getElementById('target').focus();
    return false; // prevent link navigation
}

// ─────────────────────────────────────────────
// Start Scan
// ─────────────────────────────────────────────

function startScan() {
    if (scanning) return;

    const target = document.getElementById('target').value.trim();
    const ports = document.getElementById('ports').value.trim();

    if (!target) {
        shakeElement(document.getElementById('target'));
        return;
    }

    scanning = true;
    openPortCount = 0;
    cveCount = 0;
    screenshotCount = 0;

    // Reset UI
    const btn = document.getElementById('scan-btn');
    btn.disabled = true;
    btn.classList.add('scanning');
    document.getElementById('btn-text').textContent = 'Scanning...';

    show('stats-row');
    show('progress-section');
    show('live-feed');

    document.getElementById('stat-ports').textContent = '0';
    document.getElementById('stat-cves').textContent = '0';
    document.getElementById('stat-subdomains').textContent = '0';
    document.getElementById('stat-screenshots').textContent = '0';
    document.getElementById('progress-fill').style.width = '0%';
    document.getElementById('progress-pct').textContent = '0%';
    document.getElementById('feed-container').innerHTML = '';
    document.getElementById('results-tbody').innerHTML = '';
    document.getElementById('cve-alerts').innerHTML = '';
    document.getElementById('screenshot-grid').innerHTML = '';

    hide('results-section');
    hide('cve-section');
    hide('screenshot-section');

    addFeedItem('info', `🚀 Starting scan on ${target}...`);

    socket.emit('start_scan', { target, ports });
}

// ─────────────────────────────────────────────
// Socket Events
// ─────────────────────────────────────────────

socket.on('scan_started', (data) => {
    addFeedItem('info', `🎯 Target: ${data.target} | Checking ${data.port_count} services`);
});

socket.on('scan_status', (data) => {
    document.getElementById('progress-status').textContent = data.status;
    addFeedItem('info', data.status);
});

socket.on('subdomains', (data) => {
    document.getElementById('stat-subdomains').textContent = data.count;
    if (data.count > 1) {
        addFeedItem('info', `🌐 Discovered ${data.count} related subdomains`);
    }
});

socket.on('scan_progress', (data) => {
    const pct = Math.round((data.completed / data.total) * 100);
    document.getElementById('progress-fill').style.width = pct + '%';
    document.getElementById('progress-pct').textContent = pct + '%';
});

socket.on('port_found', (data) => {
    openPortCount++;
    document.getElementById('stat-ports').textContent = openPortCount;

    const httpTag = data.is_http ? ' [Web Server]' : '';
    addFeedItem('port', `● Found: ${data.host}:${data.port} — ${data.service}${httpTag}`);

    show('results-section');
    const tbody = document.getElementById('results-tbody');
    const row = document.createElement('tr');
    row.innerHTML = `
        <td>${data.host}</td>
        <td><span class="port-badge">${data.port}</span></td>
        <td>${data.service}</td>
        <td class="banner-text">${data.banner || '—'}</td>
        <td>${data.is_http ? '<span class="http-yes">✓ Yes</span>' : '<span class="http-no">No</span>'}</td>
        <td class="cve-cell" id="cve-cell-${data.host}-${data.port}">Checking...</td>
    `;
    tbody.appendChild(row);
});

socket.on('cve_found', (data) => {
    show('cve-section');

    for (const cve of data.cves) {
        cveCount++;
        document.getElementById('stat-cves').textContent = cveCount;

        addFeedItem('cve', `🚨 Vulnerability: ${cve.id} (Severity: ${cve.score}/10)`);

        const alertDiv = document.createElement('div');
        alertDiv.className = 'cve-alert';
        alertDiv.innerHTML = `
            <div class="cve-alert-header">
                <span class="cve-id">${cve.id}</span>
                <span class="cve-score ${getScoreClass(cve.score)}">${cve.score}/10 ${cve.severity}</span>
            </div>
            <div class="cve-desc">${cve.description}</div>
            <div class="cve-target">Found on: ${data.host}:${data.port} — ${data.banner}</div>
        `;
        document.getElementById('cve-alerts').appendChild(alertDiv);

        const cell = document.getElementById(`cve-cell-${data.host}-${data.port}`);
        if (cell) {
            cell.innerHTML = `<span style="color: var(--red); font-weight: 600;">⚠ ${cveCount} found</span>`;
        }
    }
});

socket.on('screenshot_taken', (data) => {
    show('screenshot-section');
    screenshotCount++;
    document.getElementById('stat-screenshots').textContent = screenshotCount;

    addFeedItem('screenshot', `📸 Captured screenshot: ${data.url}`);

    const card = document.createElement('div');
    card.className = 'screenshot-card';
    card.innerHTML = `
        <img src="/screenshots/${data.filename}" alt="${data.url}" loading="lazy">
        <div class="screenshot-card-footer">${data.url}</div>
    `;
    document.getElementById('screenshot-grid').appendChild(card);
});

socket.on('scan_complete', (data) => {
    scanning = false;
    const btn = document.getElementById('scan-btn');
    btn.disabled = false;
    btn.classList.remove('scanning');
    document.getElementById('btn-text').textContent = 'Scan Now';
    document.getElementById('progress-status').textContent = '✅ Scan complete!';
    document.getElementById('progress-fill').style.width = '100%';
    document.getElementById('progress-pct').textContent = '100%';

    // Update cells that have no CVEs
    document.querySelectorAll('.cve-cell').forEach(cell => {
        if (cell.textContent === 'Checking...') {
            cell.innerHTML = '<span style="color: var(--green);">✓ Clean</span>';
        }
    });

    addFeedItem('info', `✅ Done — ${data.total_open} open services, ${data.total_cves} vulnerabilities found`);
});

socket.on('scan_error', (data) => {
    scanning = false;
    const btn = document.getElementById('scan-btn');
    btn.disabled = false;
    btn.classList.remove('scanning');
    document.getElementById('btn-text').textContent = 'Scan Now';
    addFeedItem('cve', `❌ Error: ${data.error}`);
});

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

function addFeedItem(type, text) {
    const container = document.getElementById('feed-container');
    const item = document.createElement('div');
    item.className = `feed-item feed-${type}`;
    item.textContent = text;
    container.insertBefore(item, container.firstChild);

    while (container.children.length > 30) {
        container.removeChild(container.lastChild);
    }
}

function getScoreClass(score) {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    return 'low';
}

function show(id) {
    document.getElementById(id).style.display = '';
}

function hide(id) {
    document.getElementById(id).style.display = 'none';
}

function shakeElement(el) {
    el.style.animation = 'none';
    el.offsetHeight;
    el.style.borderColor = 'var(--red)';
    setTimeout(() => { el.style.borderColor = ''; }, 1500);
}

// Enter key triggers scan
document.getElementById('target').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') startScan();
});
