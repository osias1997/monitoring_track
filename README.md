# App Connection Monitor

Continuously monitors TCP and UDP connections made by a running application on Windows. Includes:

- Simple CLI monitor
- Live web dashboard
- **Behavior Analyzer** — deeper reverse-engineering / behavioral analysis tool

You can install and run this on **any Windows PC** that has Python.

---

## Requirements

- Windows PC
- [Python 3.10+](https://www.python.org/downloads/) installed  
  During install, check **“Add python.exe to PATH”**
- **Administrator** recommended for the Behavior Analyzer (modules, memory, protected sockets)

---

## Install on any PC

### 1. Get the app

**Option A — from GitHub**

```bash
git clone https://github.com/osias1997/monitoring_track.git
cd monitoring_track
```

**Option B — copy the folder**

Copy this project folder to the other PC, then open that folder in a terminal.

### 2. Install dependencies

```bash
pip install -r requirements.txt
# core: pip install psutil colorama flask watchdog rich
```

---

## Behavior Analyzer (recommended for deep analysis)

Tracks what happens **before, during, and after** network connections: DLLs, cmdline/env, children, CPU/RAM spikes, file opens, registry changes, DNS, optional memory strings, and sequenced session reports.

### Configure features

Edit toggles in [`behavior_config.py`](behavior_config.py) (process inspection, files, registry, DNS, memory dump, Scapy, Frida, etc.).

### Run

```bash
# Administrator PowerShell / CMD recommended
python behavior_analyzer.py chrome
python behavior_analyzer.py --outbound-only discord
python behavior_analyzer.py   # prompts for target
```

On start you may be asked to **relaunch elevated**. Stop with **Ctrl+C**.

### Outputs

Written under `behavior_logs/`:

| File | Contents |
|------|----------|
| `events.jsonl` | Every event (JSON lines) |
| `behavior_report.md` | Markdown report with sessions + sequence |
| `behavior_report.html` | HTML report with severity flags |

### What it collects

- **Process:** loaded modules/DLLs, cmdline, interesting env vars, child processes, thread/CPU/memory spikes
- **Files:** newly opened files (`psutil`) + directory watching (`watchdog`) for configs/cookies/certs/DBs
- **Registry:** polls Internet Settings / proxy / TCPIP-related keys for changes
- **Network:** full connection metadata, DNS cache entries, heuristic SNI/host hints
- **Sequence:** events in the ~3s window before each new connection, grouped into sessions
- **Memory (optional):** URL / domain / key-like string scan on connection (`ENABLE_MEMORY_STRINGS = True`)
- **Highlights:** unusual DLLs, sensitive files then network, uncommon ports, tunnel/C2 host hints

### Optional deep hooks

Enable in `behavior_config.py` and install extras:

```bash
pip install scapy frida frida-tools
# Scapy also needs Npcap: https://npcap.com/
```

- `ENABLE_SCAPY_SNIFF` — packet sniff for DNS (and best-effort TLS-related traffic)
- `ENABLE_FRIDA_HOOKS` — attach Frida and hook `connect()`
- `ENABLE_ETW_TRACE` — notes ETW/ProcMon-style follow-up (full kernel ETW is external)

---

## Live web dashboard (lighter)

```bash
python web_dashboard.py
```

Open [http://127.0.0.1:5050](http://127.0.0.1:5050)

1. Enter an app name (`chrome`, `discord`, `notepad.exe`, …)
2. Click **Start**
3. Watch matching processes and new connections live
4. Click **Stop** when done (or Ctrl+C in the terminal)

Optional: **Outbound only**. Use **Dark / Light** to switch theme.

---

## Simple CLI monitor

```bash
python monitor_connections.py chrome
python monitor_connections.py chrome --outbound-only
```

Stop with **Ctrl+C**. Logs go to `app_connections.log`.

---

## Notes

- The target app must be **running** on that PC.
- Works for any process name or executable path — not only Chrome.
- The web dashboard is local-only (`127.0.0.1`).
- If data looks empty, run **as Administrator**.
- Use this only on systems and software you are authorized to analyze.

---

## Log fields (simple monitor)

- Timestamp
- Process name + PID
- Protocol (TCP/UDP)
- Status (ESTABLISHED, LISTEN, …)
- Direction (outbound / inbound / local)
- Local IP:port → Remote IP:port (hostname when reverse DNS succeeds)
