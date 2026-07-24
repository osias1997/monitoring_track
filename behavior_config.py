#!/usr/bin/env python3
"""
=============================================================================
 OSIDEV BEHAVIOR ANALYZER — MASTER CONFIGURATION
 Tool made by Osidev

 Toggle advanced reverse-engineering features here, then restart the analyzer.
 All modules degrade gracefully when a dependency is missing.
=============================================================================

Installation (Administrator PowerShell recommended):

  pip install -r requirements.txt
  # Packet capture also needs Npcap: https://npcap.com/
  # Frida (optional): pip install frida frida-tools
  # ETW native (optional): pip install pywintrace
  # Charts: pip install plotly

Run:
  python behavior_analyzer.py --menu
  python behavior_analyzer.py chrome --mode full
"""

from pathlib import Path

# --- Branding ---------------------------------------------------------------
TOOL_NAME = "Osidev Monitoring"
TOOL_SIGNATURE = "Tool made by Osidev"
TOOL_VERSION = "2.0.0"

# --- Target -----------------------------------------------------------------
DEFAULT_TARGET = ""

# --- Core loops -------------------------------------------------------------
POLL_INTERVAL_SEC = 0.5
HIGH_PRECISION_TIMESTAMPS = True
CORRELATION_WINDOW_SEC = 5.0       # Link related events into one behavior session
DNS_TO_CONNECT_WINDOW_SEC = 8.0    # DNS answer → TCP connect correlation window

# --- Feature toggles --------------------------------------------------------
ENABLE_PROCESS_INSPECTION = True
ENABLE_FILE_ACTIVITY = True
ENABLE_REGISTRY_WATCH = True
ENABLE_DNS_TRACKING = True
ENABLE_MEMORY_STRINGS = True       # Extract URLs/domains/keys on each new connection
ENABLE_SEQUENCE_ANALYSIS = True
ENABLE_HIGHLIGHTS = True
ENABLE_RICH_CONSOLE = True
ENABLE_COLORAMA = True
ENABLE_DLL_SIGNATURE_CHECK = True  # Authenticode validation for loaded modules
ENABLE_CORRELATION_ENGINE = True   # Strong multi-signal session grouping
ENABLE_ADVANCED_REPORT = True      # Plotly timeline / charts in HTML report

# --- Packet capture (Scapy + Npcap) ------------------------------------------
# REQUIRES: https://npcap.com/  +  pip install scapy  +  Admin
ENABLE_PACKET_CAPTURE = True
PACKET_SNIFF_TIMEOUT = 0
PACKET_PAYLOAD_PREVIEW_BYTES = 160
PACKET_EXFIL_PAYLOAD_BYTES = 4096
PACKET_MATCH_PORT_ONLY = True
PACKET_EMIT_ALL_EVENTS = False
PACKET_INTERFACE = None
PACKET_BPF_FILTER = ""
PACKET_LOG_FILE = Path("behavior_logs") / "packets.log"
PACKET_PCAP_FILE = Path("behavior_logs") / "capture.pcap"
PACKET_SUSPICIOUS_PORTS = {4444, 5555, 6666, 1234, 31337, 1337, 8081, 9001}

# --- ETW tracing ------------------------------------------------------------
# Uses PowerShell/WinEvent providers by default (no native compile needed).
# Optional native backend if `pywintrace` / `etw` is installed.
ENABLE_ETW_TRACE = True
ETW_DNS = True                     # Microsoft-Windows-DNS-Client
ETW_PROCESS = True                 # Process start/stop (best-effort)
ETW_NETWORK = True                 # TCPIP / network events (best-effort)
ETW_POLL_SEC = 2.0

# --- Frida API hooking (optional, powerful) ---------------------------------
# pip install frida frida-tools
ENABLE_FRIDA_HOOKS = False
FRIDA_HOOK_WINSOCK = True          # connect / send / recv
FRIDA_HOOK_WINHTTP = True          # WinHttpConnect / WinHttpOpenRequest / Send
FRIDA_HOOK_WININET = True          # InternetConnect / HttpSendRequest

# Legacy light sniffer (prefer ENABLE_PACKET_CAPTURE)
ENABLE_SCAPY_SNIFF = False

# --- File monitoring --------------------------------------------------------
WATCH_DIRS = [
    str(Path.home() / "AppData" / "Local"),
    str(Path.home() / "AppData" / "Roaming"),
    str(Path.home() / "Downloads"),
    r"C:\Windows\Temp",
    str(Path.home() / "AppData" / "Local" / "Temp"),
]
INTERESTING_FILE_SUFFIXES = {
    ".json", ".xml", ".ini", ".cfg", ".conf", ".config", ".db", ".sqlite",
    ".sqlite3", ".dat", ".cookie", ".cookies", ".pem", ".crt", ".cer", ".pfx",
    ".p12", ".key", ".log", ".txt", ".yml", ".yaml", ".env",
}

# --- Registry ---------------------------------------------------------------
REGISTRY_KEYS = [
    (r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "HKCU"),
    (r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections", "HKCU"),
    (r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings", "HKCU"),
    (r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "HKLM"),
    (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "HKLM"),
]

# --- Memory strings ---------------------------------------------------------
MEMORY_MAX_REGIONS = 40
MEMORY_MAX_BYTES_PER_REGION = 512 * 1024
MEMORY_STRING_MIN_LEN = 8

# --- Network / analysis -----------------------------------------------------
OUTBOUND_ONLY = False
INTERESTING_PORTS = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 3306, 3389, 8080, 8443}
SUSPICIOUS_REMOTE_HINTS = {
    "ngrok", "localtunnel", "serveo", "cloudflared", "trycloudflare",
    "duckdns", "no-ip", "dynu", "pastebin", "raw.githubusercontent",
}

# --- DLL signature ----------------------------------------------------------
DLL_SIGNATURE_CACHE_SIZE = 2000
DLL_FLAG_UNSIGNED = True
DLL_FLAG_UNTRUSTED = True

# --- Output -----------------------------------------------------------------
LOG_DIR = Path("behavior_logs")
SESSION_EVENT_LOG = LOG_DIR / "events.jsonl"
REPORT_MARKDOWN = LOG_DIR / "behavior_report.md"
REPORT_HTML = LOG_DIR / "behavior_report.html"
AUTO_REPORT_ON_EXIT = True
KEEP_LAST_N_EVENTS_IN_MEMORY = 8000

# --- Admin / UAC ------------------------------------------------------------
WARN_IF_NOT_ADMIN = True
OFFER_ELEVATION = True             # Prompt to relaunch elevated via UAC
