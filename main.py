import asyncio
import json
import struct
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# ─── Global State ────────────────────────────────────────────────────────────
scan_results = []
scan_progress = {"current": 0, "total": 0, "found": 0}
is_scanning = False
results_lock = threading.Lock()
progress_lock = threading.Lock()
scan_lock = threading.Lock()

# ─── Minecraft Protocol Helpers ───────────────────────────────────────────────

def encode_varint(value: int) -> bytes:
    """Encode an integer as a Minecraft VarInt."""
    result = b""
    while True:
        part = value & 0x7F
        value >>= 7
        if value:
            part |= 0x80
        result += bytes([part])
        if not value:
            break
    return result

def decode_varint(data: bytes, offset: int = 0):
    """Decode a VarInt from bytes, return (value, new_offset)."""
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, offset
        shift += 7
        if shift >= 35:
            break
    return None, offset

def build_handshake(ip: str, port: int, protocol_version: int = 757) -> bytes:
    """Build a Minecraft 1.7+ handshake + status request packet."""
    ip_bytes = ip.encode("utf-8")

    # Handshake packet body
    body = (
        encode_varint(0x00)                      # Packet ID
        + encode_varint(protocol_version)         # Protocol version
        + encode_varint(len(ip_bytes))            # IP length
        + ip_bytes                                # IP
        + struct.pack(">H", port)                 # Port (big-endian)
        + encode_varint(1)                        # Next state: status
    )
    packet = encode_varint(len(body)) + body

    # Status request packet
    status_req = encode_varint(1) + encode_varint(0x00)

    return packet + status_req

def clean_motd(text: str) -> str:
    """Strip Minecraft color/formatting codes (§x)."""
    result = []
    skip = False
    for ch in text:
        if ch == "§":
            skip = True
            continue
        if skip:
            skip = False
            continue
        result.append(ch)
    return "".join(result).strip()

def extract_motd(description) -> str:
    """Handle all MOTD formats: string, {text:...}, {extra:[...]}."""
    if isinstance(description, str):
        return clean_motd(description)
    if isinstance(description, dict):
        text = description.get("text", "")
        extra = description.get("extra", [])
        for part in extra:
            if isinstance(part, dict):
                text += part.get("text", "")
            elif isinstance(part, str):
                text += part
        return clean_motd(text) or "Minecraft Server"
    return "Minecraft Server"

# ─── Detection Methods ────────────────────────────────────────────────────────

async def try_modern_protocol(ip: str, port: int) -> dict | None:
    """Modern Minecraft protocol (1.7+). Returns server dict or None."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=2.5
        )
        try:
            writer.write(build_handshake(ip, port))
            await asyncio.wait_for(writer.drain(), timeout=2.0)

            # Read up to 32KB of response
            data = await asyncio.wait_for(reader.read(32768), timeout=4.0)
            if not data:
                return None

            # Find JSON start
            start = data.find(b"{")
            if start == -1:
                return None

            # Find matching closing brace
            brace_count = 0
            end = start
            for i in range(start, len(data)):
                if data[i] == ord("{"):
                    brace_count += 1
                elif data[i] == ord("}"):
                    brace_count -= 1
                    if brace_count == 0:
                        end = i + 1
                        break

            raw_json = data[start:end].decode("utf-8", errors="ignore")
            status = json.loads(raw_json)

            players = status.get("players", {})
            version = status.get("version", {})
            motd = extract_motd(status.get("description", "Minecraft Server"))

            return {
                "ip": ip, "port": port, "online": True,
                "motd": motd or "Minecraft Server",
                "players": {
                    "online": players.get("online", 0),
                    "max": players.get("max", 0),
                },
                "version": version.get("name", "Unknown"),
            }
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        return None

async def try_legacy_protocol(ip: str, port: int) -> dict | None:
    """Legacy ping for Minecraft 1.6 and older."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=2.0
        )
        try:
            legacy_ping = bytes([
                0xFE, 0x01, 0xFA, 0x00, 0x0B,
                0x00, 0x4D, 0x00, 0x43, 0x00, 0x7C,
                0x00, 0x50, 0x00, 0x69, 0x00, 0x6E,
                0x00, 0x67, 0x00, 0x48, 0x00, 0x6F,
                0x00, 0x73, 0x00, 0x74,
            ])
            writer.write(legacy_ping)
            await asyncio.wait_for(writer.drain(), timeout=1.5)

            data = await asyncio.wait_for(reader.read(512), timeout=3.0)
            if data and data[0] == 0xFF:
                # Try to decode legacy UTF-16 response
                try:
                    text = data[3:].decode("utf-16-be", errors="ignore")
                    parts = text.split("\x00")
                    motd = clean_motd(parts[0]) if parts else "Legacy Server"
                    online = int(parts[4]) if len(parts) > 4 else 0
                    max_p = int(parts[5]) if len(parts) > 5 else 0
                    version = parts[2] if len(parts) > 2 else "Legacy"
                except Exception:
                    motd, online, max_p, version = "Legacy Minecraft Server", 0, 0, "Legacy"

                return {
                    "ip": ip, "port": port, "online": True,
                    "motd": motd,
                    "players": {"online": online, "max": max_p},
                    "version": version,
                }
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        return None

async def scan_port(ip: str, port: int) -> dict | None:
    """Try all detection methods in order, return first success."""
    for method in (try_modern_protocol, try_legacy_protocol):
        result = await method(ip, port)
        if result:
            return result
    return None

# ─── Scan Engine ──────────────────────────────────────────────────────────────

async def perform_scan_async(ip: str, start_port: int, end_port: int):
    global scan_results, scan_progress, is_scanning

    semaphore = asyncio.Semaphore(1500)  # Higher concurrency than Go version

    async def scan_one(port: int):
        async with semaphore:
            result = await scan_port(ip, port)
            with progress_lock:
                scan_progress["current"] += 1
            if result:
                with results_lock:
                    scan_results.append(result)
                with progress_lock:
                    scan_progress["found"] += 1

    tasks = [scan_one(p) for p in range(start_port, end_port + 1)]
    await asyncio.gather(*tasks)

    with scan_lock:
        is_scanning = False

def run_scan_thread(ip: str, start_port: int, end_port: int):
    """Run the async scan in a dedicated thread with its own event loop."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(perform_scan_async(ip, start_port, end_port))
    finally:
        loop.close()

# ─── HTTP Server ──────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>Minecraft Server Scanner</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

        :root {
            --bg:       #0a0e14;
            --panel:    #0f1520;
            --border:   #1e2d45;
            --green:    #00ff9d;
            --blue:     #00b4ff;
            --yellow:   #ffd700;
            --red:      #ff4444;
            --dim:      #3a5068;
            --text:     #c8dcea;
            --muted:    #4a6580;
        }

        body {
            font-family: 'Syne', sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            padding: 32px 20px;
            background-image:
                radial-gradient(ellipse 80% 50% at 50% -10%, rgba(0,180,255,0.07) 0%, transparent 60%),
                repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(30,45,69,0.3) 39px, rgba(30,45,69,0.3) 40px),
                repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(30,45,69,0.15) 39px, rgba(30,45,69,0.15) 40px);
        }

        .wrap { max-width: 1200px; margin: 0 auto; }

        /* Header */
        header { display: flex; align-items: center; gap: 20px; margin-bottom: 40px; }
        .logo {
            width: 52px; height: 52px; border-radius: 12px; flex-shrink: 0;
            background: linear-gradient(135deg, #1a3a2a, #0d2a1a);
            border: 2px solid var(--green);
            display: flex; align-items: center; justify-content: center;
            box-shadow: 0 0 20px rgba(0,255,157,0.2);
        }
        .logo svg { width: 28px; height: 28px; }
        .header-text h1 {
            font-size: 2rem; font-weight: 800; letter-spacing: -0.03em;
            color: #fff;
        }
        .header-text h1 span { color: var(--green); }
        .header-text p { color: var(--muted); font-size: 0.85rem; margin-top: 2px; font-family: 'JetBrains Mono', monospace; }

        /* Panel */
        .panel {
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 28px;
            margin-bottom: 24px;
        }
        .panel-label {
            font-size: 0.7rem; font-weight: 600; letter-spacing: 0.12em;
            text-transform: uppercase; color: var(--muted);
            margin-bottom: 20px; display: flex; align-items: center; gap: 8px;
        }
        .panel-label::before {
            content: ''; display: block; width: 20px; height: 2px; background: var(--green);
        }

        /* Inputs */
        .input-row { display: flex; gap: 16px; flex-wrap: wrap; }
        .field { flex: 1; min-width: 180px; }
        .field label {
            display: block; font-size: 0.75rem; font-weight: 600;
            color: var(--muted); margin-bottom: 8px; letter-spacing: 0.05em;
            text-transform: uppercase; font-family: 'JetBrains Mono', monospace;
        }
        .field input {
            width: 100%; padding: 12px 14px;
            background: rgba(0,0,0,0.4); border: 1px solid var(--border);
            border-radius: 8px; color: #fff;
            font-family: 'JetBrains Mono', monospace; font-size: 0.95rem;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .field input:focus {
            outline: none; border-color: var(--green);
            box-shadow: 0 0 0 3px rgba(0,255,157,0.1);
        }

        .btn-row { display: flex; gap: 12px; margin-top: 24px; }
        .btn {
            padding: 12px 24px; border: none; border-radius: 8px;
            font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; font-weight: 600;
            cursor: pointer; display: flex; align-items: center; gap: 8px;
            transition: all 0.2s; letter-spacing: 0.05em;
        }
        .btn-go {
            background: var(--green); color: #000;
            box-shadow: 0 4px 20px rgba(0,255,157,0.3);
        }
        .btn-go:hover { transform: translateY(-1px); box-shadow: 0 6px 25px rgba(0,255,157,0.4); }
        .btn-go:disabled { opacity: 0.4; transform: none; cursor: not-allowed; box-shadow: none; }
        .btn-stop {
            background: transparent; color: var(--red);
            border: 1px solid var(--red);
        }
        .btn-stop:hover { background: rgba(255,68,68,0.1); }

        /* Progress */
        .progress-panel { display: none; }
        .prog-row {
            display: flex; justify-content: space-between;
            font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;
            color: var(--muted); margin-bottom: 10px;
        }
        .prog-row span:last-child { color: var(--green); font-weight: 600; }
        .bar-track {
            height: 6px; background: rgba(255,255,255,0.06);
            border-radius: 3px; overflow: hidden;
        }
        .bar-fill {
            height: 100%; width: 0%;
            background: linear-gradient(90deg, var(--green), var(--blue));
            border-radius: 3px; transition: width 0.3s ease;
            position: relative;
        }
        .bar-fill::after {
            content: ''; position: absolute; inset: 0;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            animation: shim 1.2s infinite;
        }
        @keyframes shim { 0%{transform:translateX(-100%)} 100%{transform:translateX(200%)} }

        /* Stats */
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
        .stat {
            background: var(--panel); border: 1px solid var(--border);
            border-radius: 12px; padding: 20px; text-align: center;
        }
        .stat-val {
            font-size: 1.8rem; font-weight: 800; font-family: 'JetBrains Mono', monospace;
            color: var(--green); letter-spacing: -0.03em;
        }
        .stat-key {
            font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em;
            color: var(--muted); margin-top: 4px; font-weight: 600;
        }

        /* Results */
        .results-head {
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 20px;
        }
        .badge {
            background: rgba(0,255,157,0.1); color: var(--green);
            border: 1px solid rgba(0,255,157,0.3);
            padding: 4px 12px; border-radius: 20px;
            font-size: 0.78rem; font-family: 'JetBrains Mono', monospace; font-weight: 600;
        }

        table { width: 100%; border-collapse: collapse; }
        th {
            text-align: left; padding: 10px 14px;
            font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em;
            color: var(--muted); font-weight: 600;
            border-bottom: 1px solid var(--border);
        }
        td {
            padding: 14px; border-bottom: 1px solid rgba(30,45,69,0.5);
            font-size: 0.9rem; vertical-align: middle;
        }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(0,180,255,0.03); }

        .addr {
            font-family: 'JetBrains Mono', monospace; font-weight: 600;
            color: var(--blue); background: rgba(0,180,255,0.08);
            padding: 3px 8px; border-radius: 5px;
        }
        .online-dot {
            display: inline-flex; align-items: center; gap: 6px;
            color: var(--green); font-size: 0.8rem; font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
        }
        .online-dot::before {
            content: ''; width: 7px; height: 7px; border-radius: 50%;
            background: var(--green); box-shadow: 0 0 6px var(--green);
            animation: pulse 2s infinite;
        }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        .motd-cell { color: var(--text); max-width: 280px; word-break: break-word; }
        .players {
            color: var(--yellow); font-family: 'JetBrains Mono', monospace;
            font-weight: 600; font-size: 0.85rem;
            background: rgba(255,215,0,0.07); padding: 3px 8px; border-radius: 5px;
        }
        .ver {
            color: #a78bfa; background: rgba(167,139,250,0.1);
            padding: 3px 8px; border-radius: 5px; font-size: 0.8rem;
            font-family: 'JetBrains Mono', monospace;
        }

        .empty {
            text-align: center; padding: 60px 20px; color: var(--muted);
        }
        .empty svg { opacity: 0.3; margin-bottom: 16px; }
        .empty h3 { font-size: 1.1rem; margin-bottom: 8px; color: var(--dim); }
        .empty p { font-size: 0.85rem; line-height: 1.6; }

        .spinner {
            width: 20px; height: 20px; border: 2px solid rgba(0,255,157,0.2);
            border-top-color: var(--green); border-radius: 50%;
            animation: spin 0.8s linear infinite; display: inline-block;
        }
        @keyframes spin { to { transform: rotate(360deg); } }

        @media (max-width: 700px) {
            .stats { grid-template-columns: 1fr 1fr; }
            .input-row { flex-direction: column; }
            table { font-size: 0.8rem; }
            th, td { padding: 10px 8px; }
        }
    </style>
</head>
<body>
<div class="wrap">

    <header>
        <div class="logo">
            <svg viewBox="0 0 24 24" fill="none" stroke="#00ff9d" stroke-width="2">
                <rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
            </svg>
        </div>
        <div class="header-text">
            <h1>MC <span>Scanner</span></h1>
            <p>// fast async minecraft server detector</p>
        </div>
    </header>

    <div class="panel">
        <div class="panel-label">Scan Configuration</div>
        <div class="input-row">
            <div class="field">
                <label>Target IP</label>
                <input type="text" id="ip" value="127.0.0.1" placeholder="127.0.0.1">
            </div>
            <div class="field">
                <label>Start Port</label>
                <input type="number" id="sp" value="25565" min="1" max="65535">
            </div>
            <div class="field">
                <label>End Port</label>
                <input type="number" id="ep" value="25575" min="1" max="65535">
            </div>
        </div>
        <div class="btn-row">
            <button class="btn btn-go" id="startBtn" onclick="startScan()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg>
                START SCAN
            </button>
            <button class="btn btn-stop" id="stopBtn" style="display:none" onclick="stopScan()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12"/></svg>
                STOP
            </button>
        </div>
    </div>

    <div class="panel progress-panel" id="progPanel">
        <div class="panel-label">Scan Progress</div>
        <div class="prog-row">
            <span id="progText">Initializing...</span>
            <span id="progPct">0%</span>
        </div>
        <div class="bar-track"><div class="bar-fill" id="barFill"></div></div>
    </div>

    <div class="stats" id="statsGrid" style="display:none">
        <div class="stat"><div class="stat-val" id="sScanned">0</div><div class="stat-key">Ports Scanned</div></div>
        <div class="stat"><div class="stat-val" id="sFound">0</div><div class="stat-key">Servers Found</div></div>
        <div class="stat"><div class="stat-val" id="sSpeed">0</div><div class="stat-key">Ports / sec</div></div>
        <div class="stat"><div class="stat-val" id="sTime">0s</div><div class="stat-key">Elapsed</div></div>
    </div>

    <div class="panel">
        <div class="results-head">
            <div class="panel-label" style="margin:0">Discovered Servers</div>
            <span class="badge" id="resBadge">Ready</span>
        </div>
        <div id="resultsBody">
            <div class="empty">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
                <h3>No scan running</h3>
                <p>Enter a target IP and port range,<br>then click START SCAN.</p>
            </div>
        </div>
    </div>

</div>
<script>
    let polling, speedTick, scanning = false, t0 = 0, lastCur = 0;

    function startScan() {
        const ip = document.getElementById('ip').value.trim();
        const sp = parseInt(document.getElementById('sp').value);
        const ep = parseInt(document.getElementById('ep').value);
        if (!ip || isNaN(sp) || isNaN(ep) || sp > ep || sp < 1 || ep > 65535) {
            alert('Please enter a valid IP and port range (1–65535).');
            return;
        }
        scanning = true; t0 = Date.now(); lastCur = 0;
        document.getElementById('startBtn').disabled = true;
        document.getElementById('stopBtn').style.display = 'flex';
        document.getElementById('progPanel').style.display = 'block';
        document.getElementById('statsGrid').style.display = 'grid';
        document.getElementById('resBadge').textContent = 'Scanning…';
        document.getElementById('resultsBody').innerHTML =
            '<div class="empty"><div class="spinner"></div><h3 style="margin-top:16px">Scanning ' + ip + '</h3><p>Looking for Minecraft servers…</p></div>';

        fetch('/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip, startPort: sp, endPort: ep})
        });

        polling   = setInterval(tick, 300);
        speedTick = setInterval(calcSpeed, 1000);
    }

    function stopScan() {
        scanning = false;
        clearInterval(polling); clearInterval(speedTick);
        document.getElementById('startBtn').disabled = false;
        document.getElementById('stopBtn').style.display = 'none';
        loadResults();
    }

    function tick() {
        if (!scanning) return;
        fetch('/progress').then(r => r.json()).then(d => {
            const pct = d.total > 0 ? d.current / d.total * 100 : 0;
            document.getElementById('barFill').style.width = pct + '%';
            document.getElementById('progPct').textContent = Math.round(pct) + '%';
            document.getElementById('progText').textContent =
                'Port ' + d.current + ' / ' + d.total + '  —  ' + d.found + ' server(s) found';
            document.getElementById('sScanned').textContent = d.current.toLocaleString();
            document.getElementById('sFound').textContent = d.found;
            document.getElementById('sTime').textContent = Math.floor((Date.now() - t0) / 1000) + 's';
            if (d.current >= d.total && d.total > 0) stopScan();
        });
    }

    function calcSpeed() {
        fetch('/progress').then(r => r.json()).then(d => {
            document.getElementById('sSpeed').textContent = d.current - lastCur;
            lastCur = d.current;
        });
    }

    function loadResults() {
        fetch('/results').then(r => r.json()).then(servers => {
            if (!servers || servers.length === 0) {
                document.getElementById('resBadge').textContent = 'No servers found';
                document.getElementById('resultsBody').innerHTML =
                    '<div class="empty"><h3>No servers detected</h3><p>No Minecraft servers responded in the specified port range.</p></div>';
                return;
            }
            document.getElementById('resBadge').textContent = servers.length + ' server' + (servers.length > 1 ? 's' : '') + ' found';
            let html = '<table><thead><tr><th>Address</th><th>Status</th><th>MOTD</th><th>Players</th><th>Version</th></tr></thead><tbody>';
            servers.forEach(s => {
                html += '<tr>';
                html += '<td><span class="addr">' + s.ip + ':' + s.port + '</span></td>';
                html += '<td><span class="online-dot">ONLINE</span></td>';
                html += '<td><div class="motd-cell">' + (s.motd || '—') + '</div></td>';
                html += '<td><span class="players">' + (s.players.online||0) + ' / ' + (s.players.max||0) + '</span></td>';
                html += '<td><span class="ver">' + (s.version || 'Unknown') + '</span></td>';
                html += '</tr>';
            });
            html += '</tbody></table>';
            document.getElementById('resultsBody').innerHTML = html;
        });
    }

    setInterval(() => { if (scanning) loadResults(); }, 2000);
</script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress default request logs

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            body = HTML_TEMPLATE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/progress":
            with progress_lock:
                self.send_json(dict(scan_progress))

        elif path == "/results":
            with results_lock:
                self.send_json(list(scan_results))

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        global scan_results, scan_progress, is_scanning

        if self.path != "/scan":
            self.send_response(404)
            self.end_headers()
            return

        with scan_lock:
            if is_scanning:
                self.send_response(409)
                self.end_headers()
                return
            is_scanning = True

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        req = json.loads(body)

        with results_lock:
            scan_results = []
        with progress_lock:
            scan_progress["current"] = 0
            scan_progress["total"] = req["endPort"] - req["startPort"] + 1
            scan_progress["found"] = 0

        t = threading.Thread(
            target=run_scan_thread,
            args=(req["ip"], req["startPort"], req["endPort"]),
            daemon=True,
        )
        t.start()

        self.send_response(200)
        self.end_headers()


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 5000), Handler)
    print("╔══════════════════════════════════════════╗")
    print("║   Minecraft Server Scanner (Python)      ║")
    print("║   http://localhost:5000                  ║")
    print("╚══════════════════════════════════════════╝")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
