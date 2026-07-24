"""Advanced network helpers: DNS cache, connection metadata, optional sniff."""

from __future__ import annotations

import json
import subprocess
import threading
from typing import Any

import behavior_config as cfg
from .events import BehaviorEvent, EventBus
from monitor_core import format_endpoint, infer_direction, protocol_name, resolve_hostname


def connection_details(proc_name: str, pid: int, conn) -> dict[str, Any]:
    direction = infer_direction(conn)
    remote_ip = conn.raddr.ip if conn.raddr else None
    remote_port = conn.raddr.port if conn.raddr else None
    hostname = resolve_hostname(remote_ip) if remote_ip else None
    return {
        "process": proc_name,
        "pid": pid,
        "protocol": protocol_name(conn.type),
        "status": conn.status or "NONE",
        "direction": direction,
        "local": format_endpoint(conn.laddr, resolve=False),
        "remote": format_endpoint(conn.raddr, resolve=True),
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "hostname": hostname,
        "likely_https": remote_port in (443, 8443),
        "likely_dns": remote_port == 53,
        "sni_hint": hostname,  # true SNI needs packet capture (Scapy/Npcap)
        "user_agent_hint": None,  # requires HTTP interception / Frida / sniff
    }


def fetch_dns_cache() -> list[dict[str, Any]]:
    """Best-effort DNS client cache via PowerShell."""
    if not cfg.ENABLE_DNS_TRACKING:
        return []
    ps = (
        "Get-DnsClientCache | Select-Object Name, Type, Data, TimeToLive | "
        "ConvertTo-Json -Compress"
    )
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            return []
        data = json.loads(completed.stdout)
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return []
    return []


class DnsTracker:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._seen: set[tuple] = set()

    def poll(self) -> None:
        for row in fetch_dns_cache():
            name = row.get("Name")
            data = row.get("Data")
            typ = row.get("Type")
            key = (name, data, typ)
            if not name or key in self._seen:
                continue
            self._seen.add(key)
            self.bus.emit(BehaviorEvent(
                category="dns",
                action="dns_cache_entry",
                summary=f"DNS: {name} → {data} ({typ})",
                details=row,
                interesting=False,
            ))


class OptionalPacketSniffer:
    """Optional Scapy sniffer for SNI / DNS query names (needs Npcap + admin)."""

    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self, pids: set[int] | None = None) -> bool:
        if not cfg.ENABLE_SCAPY_SNIFF:
            return False
        try:
            from scapy.all import DNS, DNSQR, TCP, IP, AsyncSniffer  # type: ignore
        except Exception:
            self.bus.emit(BehaviorEvent(
                category="system",
                action="scapy_unavailable",
                summary="Scapy/Npcap unavailable — packet sniff disabled",
            ))
            return False

        bus = self.bus
        stop = self._stop

        def _handle(pkt):
            try:
                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                    qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                    bus.emit(BehaviorEvent(
                        category="dns",
                        action="dns_query_sniffed",
                        summary=f"DNS query sniffed: {qname}",
                        details={"qname": qname},
                        interesting=True,
                    ))
                # TLS ClientHello / SNI is version-dependent; keep best-effort
                if pkt.haslayer(TCP) and pkt.haslayer(IP):
                    raw = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
                    if b"\x00\x00" in raw and b"." in raw and len(raw) > 40:
                        # Heuristic only — full SNI parse needs proper TLS layer
                        pass
            except Exception:
                return

        try:
            sniffer = AsyncSniffer(prn=_handle, store=False, filter="udp port 53 or tcp port 443")
            sniffer.start()
            self._thread = sniffer  # type: ignore
            bus.emit(BehaviorEvent(
                category="system",
                action="scapy_started",
                summary="Scapy packet sniffer started (DNS/443)",
            ))
            return True
        except Exception as exc:
            bus.emit(BehaviorEvent(
                category="system",
                action="scapy_failed",
                summary=f"Scapy sniff failed: {exc}",
            ))
            return False

    def stop(self) -> None:
        self._stop.set()
        sniffer = self._thread
        if sniffer is not None and hasattr(sniffer, "stop"):
            try:
                sniffer.stop()
            except Exception:
                pass
