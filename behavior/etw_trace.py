"""
ETW / Windows Event tracing for DNS, process, and network activity.

Backends (first available wins):
  1. Native `etw` / `pywintrace` if installed
  2. PowerShell Get-WinEvent polling (works on stock Windows with Admin)

Providers used (best-effort):
  - Microsoft-Windows-DNS-Client/Operational
  - Microsoft-Windows-Kernel-Process/Analytic (when accessible)
  - Microsoft-Windows-TCPIP/Diagnostic (when accessible)

Tool made by Osidev
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
from typing import Any

import behavior_config as cfg
from .events import BehaviorEvent, EventBus


def _ps(command: str, timeout: float = 12.0) -> str:
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return completed.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


class EtwTracer:
    """Background ETW-like event pump scoped loosely to monitored PIDs."""

    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._pids: set[int] = set()
        self._seen: set[str] = set()
        self._lock = threading.Lock()
        self._backend = "none"

    def update_pids(self, pids: set[int]) -> None:
        with self._lock:
            self._pids = set(pids)

    def start(self) -> bool:
        if not cfg.ENABLE_ETW_TRACE:
            return False
        if self._thread and self._thread.is_alive():
            return True

        # Prefer native backend if present
        if self._try_native_start():
            self._backend = "native"
        else:
            self._backend = "winevent"
            self._stop.clear()
            self._thread = threading.Thread(target=self._winevent_loop, daemon=True)
            self._thread.start()

        self.bus.emit(BehaviorEvent(
            category="system",
            action="etw_started",
            summary=f"ETW tracing started (backend={self._backend})",
            details={"backend": self._backend, "dns": cfg.ETW_DNS, "process": cfg.ETW_PROCESS, "network": cfg.ETW_NETWORK},
            interesting=True,
        ))
        return True

    def _try_native_start(self) -> bool:
        """Attempt pywintrace/etw; return False to fall back."""
        try:
            import etw  # type: ignore  # noqa: F401
        except Exception:
            try:
                import pywintrace  # type: ignore  # noqa: F401
            except Exception:
                return False
        # Native session wiring varies by package version — keep fallback primary for stability.
        # Emit a note so users know the package is present for future extension.
        self.bus.emit(BehaviorEvent(
            category="system",
            action="etw_native_available",
            summary="Native ETW package detected — using WinEvent poller for stable capture",
        ))
        return False

    def _winevent_loop(self) -> None:
        while not self._stop.is_set():
            try:
                if cfg.ETW_DNS:
                    self._poll_dns_client()
                if cfg.ETW_PROCESS:
                    self._poll_process_events()
                if cfg.ETW_NETWORK:
                    self._poll_network_hints()
            except Exception as exc:
                self.bus.emit(BehaviorEvent(
                    category="system",
                    action="etw_poll_error",
                    summary=f"ETW poll error: {exc}",
                ))
            self._stop.wait(cfg.ETW_POLL_SEC)

    def _emit_unique(self, key: str, event: BehaviorEvent) -> None:
        if key in self._seen:
            return
        self._seen.add(key)
        if len(self._seen) > 20000:
            # prevent unbounded growth
            self._seen = set(list(self._seen)[-10000:])
        self.bus.emit(event)

    def _poll_dns_client(self) -> None:
        # Event 3008 / 3010 often carry query names on DNS Client Operational log
        ps = r"""
$ErrorActionPreference='SilentlyContinue'
$events = Get-WinEvent -LogName 'Microsoft-Windows-DNS-Client/Operational' -MaxEvents 40
$result = @()
foreach ($e in $events) {
  $msg = $e.Message
  if ($msg -match '(?i)name\s*[:=]\s*([A-Za-z0-9\.\-_]+)') { $q=$Matches[1] } else { $q=$null }
  $result += [pscustomobject]@{
    Id=$e.Id; Time=$e.TimeCreated.ToString('o'); Query=$q; Message=($msg.Substring(0,[Math]::Min(240,$msg.Length)))
  }
}
$result | ConvertTo-Json -Compress
"""
        raw = _ps(ps)
        if not raw.strip():
            return
        try:
            rows = json.loads(raw)
        except json.JSONDecodeError:
            return
        if isinstance(rows, dict):
            rows = [rows]
        for row in rows or []:
            q = row.get("Query")
            if not q:
                continue
            key = f"dns:{row.get('Id')}:{row.get('Time')}:{q}"
            self._emit_unique(key, BehaviorEvent(
                category="etw",
                action="etw_dns",
                summary=f"ETW DNS: {q}",
                details=row,
                interesting=True,
            ))

    def _poll_process_events(self) -> None:
        with self._lock:
            pids = set(self._pids)
        if not pids:
            return
        # Security/Sysmon may be absent; use recent process creation via Get-Process delta is handled elsewhere.
        # Here we watch for child process starts using WMI-ish WinEvent 4688 when available.
        ps = r"""
$ErrorActionPreference='SilentlyContinue'
try {
  $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 25
} catch { return }
$events | ForEach-Object {
  $msg = $_.Message
  [pscustomobject]@{
    Time=$_.TimeCreated.ToString('o')
    Message=($msg.Substring(0,[Math]::Min(300,$msg.Length)))
  }
} | ConvertTo-Json -Compress
"""
        raw = _ps(ps, timeout=15)
        if not raw.strip():
            return
        try:
            rows = json.loads(raw)
        except json.JSONDecodeError:
            return
        if isinstance(rows, dict):
            rows = [rows]
        for row in rows or []:
            msg = str(row.get("Message") or "")
            # Only keep if any monitored PID appears in the message
            if not any(str(pid) in msg for pid in pids):
                continue
            key = f"proc:{row.get('Time')}:{hash(msg) & 0xffffffff}"
            self._emit_unique(key, BehaviorEvent(
                category="etw",
                action="etw_process",
                summary="ETW process create related to monitored PID",
                details=row,
                interesting=True,
            ))

    def _poll_network_hints(self) -> None:
        # Lightweight: surface recent firewall/connection noise if log exists
        ps = r"""
$ErrorActionPreference='SilentlyContinue'
try {
  $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; Id=2004,2006} -MaxEvents 10
} catch { return }
$events | ForEach-Object {
  [pscustomobject]@{
    Id=$_.Id; Time=$_.TimeCreated.ToString('o');
    Message=($_.Message.Substring(0,[Math]::Min(220,$_.Message.Length)))
  }
} | ConvertTo-Json -Compress
"""
        raw = _ps(ps)
        if not raw.strip():
            return
        try:
            rows = json.loads(raw)
        except json.JSONDecodeError:
            return
        if isinstance(rows, dict):
            rows = [rows]
        for row in rows or []:
            key = f"net:{row.get('Id')}:{row.get('Time')}"
            self._emit_unique(key, BehaviorEvent(
                category="etw",
                action="etw_network",
                summary=f"ETW network/firewall event {row.get('Id')}",
                details=row,
                interesting=False,
            ))

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None
        if self._backend != "none":
            self.bus.emit(BehaviorEvent(
                category="system",
                action="etw_stopped",
                summary="ETW tracing stopped",
            ))
