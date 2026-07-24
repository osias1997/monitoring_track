# App Connection Monitor

Continuously monitors TCP and UDP connections made by a running application and logs them to the console and `app_connections.log`.

## Setup

```bash
pip install -r requirements.txt
# or: pip install psutil colorama
```

On Windows, run the terminal **as Administrator** if you need connections for protected processes (some apps hide sockets otherwise).

## Usage

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

Each new connection records:

- Timestamp
- Process name + PID
- Protocol (TCP/UDP)
- Status (ESTABLISHED, LISTEN, …)
- Direction (outbound / inbound / local)
- Local IP:port → Remote IP:port (hostname when reverse DNS succeeds)
