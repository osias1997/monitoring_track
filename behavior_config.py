#!/usr/bin/env python3
"""
=============================================================================
 BEHAVIOR ANALYZER — CONFIGURATION
 Toggle features on/off here. Restart the analyzer after changing settings.
=============================================================================
"""

from pathlib import Path

# --- Branding ---------------------------------------------------------------
TOOL_NAME = "Osidev Monitoring"
TOOL_SIGNATURE = "Tool made by Osidev"

# --- Target (can also be passed on the CLI) ---------------------------------
DEFAULT_TARGET = ""  # e.g. "chrome" or full path; empty = prompt / CLI arg

# --- Core loops -------------------------------------------------------------
POLL_INTERVAL_SEC = 0.5          # How often to scan processes / connections
HIGH_PRECISION_TIMESTAMPS = True  # Include microseconds in event times

# --- Feature toggles --------------------------------------------------------
ENABLE_PROCESS_INSPECTION = True   # DLLs, cmdline, env, children, CPU/RAM
ENABLE_FILE_ACTIVITY = True        # Open files + watchdog on interesting dirs
ENABLE_REGISTRY_WATCH = True       # Poll network-related registry keys
ENABLE_DNS_TRACKING = True         # DNS cache + port-53 correlations
ENABLE_MEMORY_STRINGS = False      # Optional: dump URL/key-like strings on connect
ENABLE_SEQUENCE_ANALYSIS = True    # Build before/during/after event chains
ENABLE_HIGHLIGHTS = True           # Flag interesting / suspicious patterns
ENABLE_RICH_CONSOLE = True         # Pretty console (falls back if rich missing)
ENABLE_COLORAMA = True

# Optional deep hooks (require extra packages / drivers — safe no-ops if off)
ENABLE_SCAPY_SNIFF = False         # Needs: pip install scapy + Npcap
ENABLE_FRIDA_HOOKS = False         # Needs: pip install frida frida-tools
ENABLE_ETW_TRACE = False           # Experimental PowerShell/ETW helper (best-effort)

# --- File monitoring --------------------------------------------------------
# Directories watched for create/modify near connection time (watchdog)
WATCH_DIRS = [
    str(Path.home() / "AppData" / "Local"),
    str(Path.home() / "AppData" / "Roaming"),
    str(Path.home() / "Downloads"),
    r"C:\Windows\Temp",
    str(Path.home() / "AppData" / "Local" / "Temp"),
]
# Interesting file suffixes to emphasize in reports
INTERESTING_FILE_SUFFIXES = {
    ".json", ".xml", ".ini", ".cfg", ".conf", ".config", ".db", ".sqlite",
    ".sqlite3", ".dat", ".cookie", ".cookies", ".pem", ".crt", ".cer", ".pfx",
    ".p12", ".key", ".log", ".txt", ".yml", ".yaml", ".env",
}

# --- Registry keys to poll (HKCU / HKLM relative paths) ---------------------
REGISTRY_KEYS = [
    (r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "HKCU"),
    (r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections", "HKCU"),
    (r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings", "HKCU"),
    (r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "HKLM"),
    (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "HKLM"),
]

# --- Memory strings (only if ENABLE_MEMORY_STRINGS) -------------------------
MEMORY_MAX_REGIONS = 40            # Cap regions scanned per snapshot
MEMORY_MAX_BYTES_PER_REGION = 512 * 1024
MEMORY_STRING_MIN_LEN = 8

# --- Network / analysis -----------------------------------------------------
OUTBOUND_ONLY = False
INTERESTING_PORTS = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 3306, 3389, 8080, 8443}
# Remotes commonly used for C2 / tunnels (heuristic — not definitive)
SUSPICIOUS_REMOTE_HINTS = {
    "ngrok", "localtunnel", "serveo", "cloudflared", "trycloudflare",
    "duckdns", "no-ip", "dynu", "pastebin", "raw.githubusercontent",
}

# --- Output -----------------------------------------------------------------
LOG_DIR = Path("behavior_logs")
SESSION_EVENT_LOG = LOG_DIR / "events.jsonl"
REPORT_MARKDOWN = LOG_DIR / "behavior_report.md"
REPORT_HTML = LOG_DIR / "behavior_report.html"
AUTO_REPORT_ON_EXIT = True
KEEP_LAST_N_EVENTS_IN_MEMORY = 5000

# --- Admin ------------------------------------------------------------------
WARN_IF_NOT_ADMIN = True
OFFER_ELEVATION = True             # Prompt to relaunch elevated on Windows
