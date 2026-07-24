# Osidev Monitoring

**Tool made by Osidev** · Windows behavioral reverse-engineering toolkit

Monitors a running application and records what happens before, during, and after network activity.

Includes:

- Simple CLI connection monitor
- Live web dashboard (with save/export)
- **Behavior Analyzer v2** — process, file, registry, DNS, packets, ETW, Frida, memory, DLL signatures, correlation, Plotly HTML reports

---

## Requirements

- Windows 10/11
- [Python 3.10+](https://www.python.org/downloads/) (**Add to PATH**)
- **Run as Administrator** for full power (UAC elevation prompt is built-in)
- [Npcap](https://npcap.com/) for packet capture (enable WinPcap-compatible mode)

---

## Install

```bash
git clone https://github.com/osias1997/monitoring_track.git
cd monitoring_track
pip install -r requirements.txt
```

Optional deep hooks:

```bash
pip install frida frida-tools
# optional native ETW: pip install pywintrace
```

---

## Behavior Analyzer v2

### Config (`behavior_config.py`)

Toggle anything without editing code:

| Flag | Purpose |
|------|---------|
| `ENABLE_PACKET_CAPTURE` | Scapy process-scoped sniff → `packets.log` + `capture.pcap` |
| `ENABLE_ETW_TRACE` | DNS / process / network WinEvent tracing |
| `ENABLE_FRIDA_HOOKS` | Winsock / WinHTTP / WinINet API hooks |
| `ENABLE_MEMORY_STRINGS` | URL/domain/key-like strings on each new connection |
| `ENABLE_DLL_SIGNATURE_CHECK` | Authenticode validation for loaded modules |
| `ENABLE_CORRELATION_ENGINE` | Group related events into behavior sessions |
| `ENABLE_ADVANCED_REPORT` | Plotly timeline / charts in HTML report |
| `OFFER_ELEVATION` | UAC relaunch prompt when not admin |

### Run

```bash
# Interactive menu (recommended)
python behavior_analyzer.py --menu

# Modes
python behavior_analyzer.py chrome --mode full
python behavior_analyzer.py chrome --mode deep      # ETW + Frida + memory + packets
python behavior_analyzer.py chrome --mode packets
python behavior_analyzer.py chrome --mode connections
python behavior_analyzer.py chrome --mode light

# Force individual capabilities
python behavior_analyzer.py chrome --etw --frida --memory --packets
```

Stop with **Ctrl+C** → professional report is generated automatically.

### What it collects

- **Process:** cmdline, env, children, CPU/RAM/thread spikes, loaded DLLs
- **DLL signatures:** Authenticode Valid / NotSigned / NotTrusted
- **Files:** open-file polling + watchdog on AppData/Temp/Downloads
- **Registry:** Internet Settings / proxy / TCPIP key changes
- **Network:** connection metadata + DNS cache
- **Packets:** protocol, endpoints, size, TCP flags, hex/ASCII, HTTP Host, DNS, TLS SNI, exfil heuristics
- **ETW:** DNS Client Operational + process/network WinEvents (Admin)
- **Frida (optional):** `connect` / `send` / `recv`, WinHttp*, WinINet*
- **Memory:** strings dump on connection events
- **Correlation:** DNS→connect, file/registry→network, Frida→network sessions

### Outputs (`behavior_logs/`)

| File | Contents |
|------|----------|
| `events.jsonl` | Every event |
| `behavior_report.md` | Markdown session report |
| `behavior_report.html` | Professional HTML + Plotly charts |
| `packets.log` | Packet text log |
| `capture.pcap` | Wireshark-ready capture |

---

## Live web dashboard

```bash
python web_dashboard.py
```

Open http://127.0.0.1:5050

- Live process + connection feed
- Dark mode
- **Save to disk** / download JSON·MD·CSV·TXT / download log → `web_exports/`

---

## Simple CLI

```bash
python monitor_connections.py chrome
python monitor_connections.py chrome --outbound-only
```

---

## Architecture (modular)

```
behavior_config.py          # master toggles
behavior_analyzer.py        # orchestrator + modes + UAC
behavior/
  etw_trace.py              # ETW / WinEvent
  frida_hooks.py            # API hooking
  packet_capture.py         # Scapy process-scoped capture
  dll_signer.py             # Authenticode
  correlation.py            # behavior sessions
  memory_strings.py         # on-connection dumps
  process_inspect.py        # modules / children / resources
  file_activity.py          # open files + watchdog
  registry_watch.py         # registry polling
  report.py                 # Markdown + Plotly HTML
  ...
```

---

## Notes

- Target app must be **running**
- Use only on systems/software you are authorized to analyze
- Without Admin/Npcap, core process monitoring still works; advanced modules report clear errors
