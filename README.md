# Minecraft Server Scanner (Python) — Documentation

A fast, async Python web tool that scans a target IP across a port range to detect active Minecraft servers. Built with zero external dependencies — pure Python stdlib only.

---

## How to Run

```bash
# Requirements: Python 3.7 or newer
# No pip installs needed!

python3 main.py

# Then open your browser at:
http://localhost:5000
```

---

## How It Works — Overview

```
Browser (http://localhost:5000)
    │
    ├── POST /scan  ──────────────────────────────────────────────────┐
    │                                                                  ▼
    │                                               threading.Thread (background)
    │                                                        │
    │                                               asyncio event loop
    │                                                        │
    │                                               asyncio.gather()
    │                                               (1500 concurrent tasks)
    │                                                        │
    │                                               scan_port(ip, port)
    │                                                   │
    │                                                   ├── try_modern_protocol()
    │                                                   └── try_legacy_protocol()
    │
    ├── GET /progress  ◄── polled every 300ms (progress bar + stats)
    └── GET /results   ◄── polled every 2s   (server table)
```

---

## HTTP Routes

| Route | Method | Description |
|---|---|---|
| `/` | GET | Serves the full HTML/CSS/JS frontend |
| `/scan` | POST | Starts a background async scan |
| `/progress` | GET | Returns scan progress as JSON |
| `/results` | GET | Returns all found servers as JSON |

---

## Scan Flow (Step by Step)

### 1. Browser Sends Scan Request (`POST /scan`)

```json
{
  "ip": "127.0.0.1",
  "startPort": 25565,
  "endPort": 25575
}
```

`Handler.do_POST` validates the request, resets global state, then spawns a **daemon thread** that runs the async scan so the HTTP response returns instantly.

---

### 2. Async Engine (`perform_scan_async`)

```python
semaphore = asyncio.Semaphore(1500)
tasks = [scan_one(p) for p in range(start_port, end_port + 1)]
await asyncio.gather(*tasks)
```

A **semaphore** limits concurrent coroutines to 1500 at a time. `asyncio.gather()` runs all port tasks concurrently — I/O waits (connecting, reading) don't block other tasks, making this very fast across large port ranges.

Each task:
1. Acquires a semaphore slot
2. Calls `scan_port()` for its port
3. Updates shared progress counters (thread-safe via `threading.Lock`)
4. Releases the slot

---

### 3. Server Detection — 2 Methods

Each port is tested in order. The first method that gets a valid response wins.

#### Method 1: `try_modern_protocol` — Minecraft 1.7+

Builds a proper **Minecraft handshake packet** then sends a **status request**:

```
Handshake packet:
  VarInt(packet_length)
  0x00               → Packet ID
  VarInt(757)        → Protocol version (1.18)
  VarInt(len(ip))    → IP string length
  <ip bytes>         → IP address
  UInt16 (big-endian)→ Port
  VarInt(1)          → Next state = status (1)

Status request:
  VarInt(1) + VarInt(0x00)
```

Reads up to 32KB of response and scans for a `{` character. Then walks forward to find the matching `}` to extract a clean JSON string. Parsed fields:

| JSON field | Maps to |
|---|---|
| `description` | MOTD (string or object) |
| `players.online` | Current player count |
| `players.max` | Max player slots |
| `version.name` | Server version string |

#### Method 2: `try_legacy_protocol` — Minecraft 1.6 and older

Sends the legacy **0xFE ping packet**. If the server replies with `0xFF` as the first byte, it's a legacy server. The rest of the response is decoded as **UTF-16 BE**, split on null bytes to extract:

```
parts[0] → MOTD
parts[2] → Version
parts[4] → Online player count
parts[5] → Max players
```

---

### 4. VarInt Encoding / Decoding

Minecraft uses a variable-length integer format for packet framing:

```python
def encode_varint(value: int) -> bytes:
    result = b""
    while True:
        part = value & 0x7F       # take 7 bits
        value >>= 7
        if value:
            part |= 0x80          # set "more bytes follow" flag
        result += bytes([part])
        if not value:
            break
    return result
```

Each byte encodes 7 bits of data. The MSB (`0x80`) signals that more bytes follow.

---

### 5. MOTD Parsing (`extract_motd`)

The `description` field in a Minecraft status response can take three different shapes:

```python
# Shape 1: plain string
"description": "A Minecraft Server"

# Shape 2: object with text key
"description": { "text": "A Minecraft Server" }

# Shape 3: object with extra array (rich text)
"description": {
  "text": "",
  "extra": [
    { "text": "Welcome ", "color": "gold" },
    { "text": "to SpyMC!", "bold": true }
  ]
}
```

All three are handled and color codes (`§a`, `§l`, `§r`, etc.) are stripped by `clean_motd()`.

---

### 6. Progress & Results Polling

**`GET /progress`** response:
```json
{ "current": 8, "total": 11, "found": 2 }
```

**`GET /results`** response:
```json
[
  {
    "ip": "127.0.0.1",
    "port": 25565,
    "online": true,
    "motd": "Welcome to SpyMC!",
    "players": { "online": 12, "max": 100 },
    "version": "1.20.1"
  }
]
```

The browser polls `/progress` every **300ms** (for the progress bar) and `/results` every **2s** (to refresh the server table).

---

## Thread Safety

All shared global state is protected with `threading.Lock`:

| Variable | Lock | Purpose |
|---|---|---|
| `scan_results` | `results_lock` | List of discovered servers |
| `scan_progress` | `progress_lock` | current / total / found counters |
| `is_scanning` | `scan_lock` | Prevents two scans running at once |

The async scan runs inside a **daemon thread** with its own event loop (`asyncio.new_event_loop()`), isolated from the HTTP server's thread.

---

## Key Data Structures

```python
# Global state
scan_results  = []          # List of server dicts
scan_progress = {
    "current": 0,           # Ports checked so far
    "total":   0,           # Total ports in range
    "found":   0,           # Servers discovered
}
is_scanning = False         # Prevents duplicate scans

# Each discovered server dict
{
    "ip":      "127.0.0.1",
    "port":    25565,
    "online":  True,
    "motd":    "A Minecraft Server",
    "players": { "online": 0, "max": 20 },
    "version": "1.20.1",
}
```

---

## Timeouts

| Stage | Timeout |
|---|---|
| TCP connection (modern) | 2.5 seconds |
| TCP drain / write (modern) | 2.0 seconds |
| Read response (modern) | 4.0 seconds |
| TCP connection (legacy) | 2.0 seconds |
| TCP drain / write (legacy) | 1.5 seconds |
| Read response (legacy) | 3.0 seconds |

---

## Python vs Go — Key Differences

| | Go Version | Python Version |
|---|---|---|
| Concurrency model | Goroutines + channel semaphore | `asyncio` + `asyncio.Semaphore` |
| Max concurrency | 1000 | **1500** |
| Detection methods | 4 (incl. false-positive methods) | **2 (protocol-accurate only)** |
| Legacy MOTD | Returns `"Legacy Server"` string | **Decodes real MOTD, version, players** |
| JSON extraction | Stops at first `{` | **Matches braces to find clean JSON** |
| External dependencies | None (Go stdlib) | **None (Python stdlib)** |

---

## Limitations & Notes

- **No stop endpoint** — clicking Stop in the browser halts frontend polling, but backend coroutines continue until all ports finish. Adding a `asyncio.Event` cancel flag would fix this.
- **Single scan at a time** — a second `POST /scan` while one is running returns HTTP 409 Conflict.
- **Local/authorised use only** — only scan IPs and networks you own or have explicit permission to test.
- **High concurrency on slow machines** — reduce `asyncio.Semaphore(1500)` to `500` if you see connection errors on low-RAM machines.
- **Python 3.7+ required** — uses `asyncio.open_connection`, f-strings, and `asyncio.gather`.
