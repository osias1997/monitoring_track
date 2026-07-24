# App Connection Monitor

Continuously monitors TCP and UDP connections made by a running application.

## Setup

```bash
pip install -r requirements.txt
# or: pip install psutil colorama flask
```

On Windows, run the terminal **as Administrator** if you need connections for protected processes (some apps hide sockets otherwise).

## Live web dashboard

```bash
python web_dashboard.py
```

Open [http://127.0.0.1:5050](http://127.0.0.1:5050) in your browser.

- Enter any app name or executable path (`chrome`, `discord`, `notepad.exe`, …)
- Press **Start** to watch matching processes and new connections live
- Optional: enable **Outbound only**
- Press **Stop** or Ctrl+C in the terminal to end the session

## CLI usage

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

## Log fields

Both the CLI and web dashboard append events to `app_connections.log`:

- Timestamp
- Process name + PID
- Protocol (TCP/UDP)
- Status (ESTABLISHED, LISTEN, …)
- Direction (outbound / inbound / local)
- Local IP:port → Remote IP:port (hostname when reverse DNS succeeds)
