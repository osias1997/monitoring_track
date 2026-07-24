# App Connection Monitor

Continuously monitors TCP and UDP connections made by a running application on Windows. Includes a CLI and a live web dashboard.

You can install and run this on **any Windows PC** that has Python.

---

## Requirements

- Windows PC
- [Python 3.10+](https://www.python.org/downloads/) installed  
  During install, check **“Add python.exe to PATH”**
- Optional but useful: run **Command Prompt / PowerShell as Administrator** (some apps hide network sockets without it)

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
# or: pip install psutil colorama flask
```

### 3. Run the live web monitor

```bash
python web_dashboard.py
```

Open [http://127.0.0.1:5050](http://127.0.0.1:5050) in your browser.

1. Enter an app name (`chrome`, `discord`, `notepad.exe`, …)
2. Click **Start**
3. Watch matching processes and new connections live
4. Click **Stop** when done (or press Ctrl+C in the terminal)

Optional: enable **Outbound only** to filter the feed.

Use the **Dark / Light** button to switch theme (preference is saved in the browser).

### 4. Or use the terminal (CLI) version

```bash
# Interactive prompt for the app name
python monitor_connections.py

# Pass the app name / path directly
python monitor_connections.py chrome
python monitor_connections.py firefox
python monitor_connections.py "C:\Program Files\Discord\Discord.exe"

# Only outbound connections
python monitor_connections.py chrome --outbound-only
```

Stop with **Ctrl+C**. A summary of unique remote endpoints is printed at the end.

---

## Notes

- The app you want to monitor must be **running** on that PC.
- Works for any process name or executable path — not only Chrome.
- The dashboard is local-only (`127.0.0.1`) — it monitors that PC, not remote PCs over the network.
- If connections look empty, restart the terminal **as Administrator** and try again.
- Events from both the CLI and web dashboard are written to `app_connections.log`.

---

## Log fields

Each new connection records:

- Timestamp
- Process name + PID
- Protocol (TCP/UDP)
- Status (ESTABLISHED, LISTEN, …)
- Direction (outbound / inbound / local)
- Local IP:port → Remote IP:port (hostname when reverse DNS succeeds)
