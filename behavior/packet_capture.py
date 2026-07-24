"""
Deep packet capture for monitored processes (Scapy + Npcap).

REQUIREMENTS (Windows):
  1. Install Npcap from https://npcap.com/
     - During install, enable "WinPcap API-compatible Mode"
  2. pip install scapy
  3. Run this tool as Administrator

Packets are filtered to local IP:port pairs owned by the target PID(s),
updated live from psutil connection tables so capture stays process-scoped.
"""

from __future__ import annotations

import threading
from collections import deque
from pathlib import Path
from typing import Any, Callable

import behavior_config as cfg
from .events import BehaviorEvent, EventBus, now_ts


def _payload_views(data: bytes, limit: int | None = None) -> dict[str, str]:
    limit = limit or cfg.PACKET_PAYLOAD_PREVIEW_BYTES
    chunk = data[:limit]
    hex_view = " ".join(f"{b:02x}" for b in chunk)
    ascii_view = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return {"hex": hex_view, "ascii": ascii_view, "preview_len": len(chunk)}


def _tcp_flags(tcp) -> list[str]:
    names = []
    mapping = [
        ("FIN", "F"),
        ("SYN", "S"),
        ("RST", "R"),
        ("PSH", "P"),
        ("ACK", "A"),
        ("URG", "U"),
        ("ECE", "E"),
        ("CWR", "C"),
    ]
    # Scapy FlagValue supports "in" checks like "S" in tcp.flags
    flags = str(tcp.flags)
    for name, letter in mapping:
        if letter in flags:
            names.append(name)
    return names


def _parse_http(payload: bytes) -> dict[str, Any] | None:
    try:
        text = payload.decode("utf-8", errors="ignore")
    except Exception:
        return None
    if not text:
        return None
    first = text.split("\r\n", 1)[0]
    methods = ("GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "HTTP/")
    if not any(first.startswith(m) for m in methods):
        return None
    headers: dict[str, str] = {}
    host = None
    user_agent = None
    for line in text.split("\r\n")[1:]:
        if not line:
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    host = headers.get("host")
    user_agent = headers.get("user-agent")
    return {
        "request_line": first[:200],
        "host": host,
        "user_agent": user_agent,
        "headers_sample": dict(list(headers.items())[:12]),
    }


def _extract_sni_from_clienthello(data: bytes) -> str | None:
    """Best-effort TLS ClientHello SNI parser (no full TLS stack required)."""
    if len(data) < 6 or data[0] != 0x16:  # Handshake record
        return None
    # Find extension type 0x0000 (server_name)
    idx = data.find(b"\x00\x00")
    # Search for server_name extension more carefully
    i = 0
    while i < len(data) - 9:
        if data[i : i + 2] == b"\x00\x00":
            ext_len = int.from_bytes(data[i + 2 : i + 4], "big")
            if ext_len > 0 and i + 4 + ext_len <= len(data):
                # list length + type + name length
                j = i + 4
                if j + 5 <= len(data) and data[j + 2] == 0x00:  # host_name
                    namelen = int.from_bytes(data[j + 3 : j + 5], "big")
                    name = data[j + 5 : j + 5 + namelen]
                    try:
                        sni = name.decode("utf-8", errors="ignore")
                        if "." in sni and len(sni) > 2:
                            return sni
                    except Exception:
                        pass
        i += 1
    return None


def _parse_dns(pkt) -> dict[str, Any] | None:
    try:
        from scapy.all import DNS, DNSQR, DNSRR  # type: ignore
    except Exception:
        return None
    if not pkt.haslayer(DNS):
        return None
    dns = pkt[DNS]
    info: dict[str, Any] = {"id": int(dns.id), "qr": int(dns.qr)}
    if pkt.haslayer(DNSQR):
        q = pkt[DNSQR]
        info["qname"] = q.qname.decode(errors="ignore").rstrip(".")
        info["qtype"] = int(q.qtype)
    answers = []
    if getattr(dns, "an", None):
        try:
            for i in range(dns.ancount):
                rr = dns.an[i]
                answers.append(str(rr.rdata))
        except Exception:
            pass
    if answers:
        info["answers"] = answers[:8]
    return info


class ProcessPacketCapture:
    """
    Background Scapy sniffer scoped to monitored process endpoints.

    Main thread should periodically call update_process_endpoints(pids).
    """

    def __init__(self, bus: EventBus, on_packet: Callable[[dict], None] | None = None) -> None:
        self.bus = bus
        self.on_packet = on_packet
        self._lock = threading.Lock()
        # (ip, port) pairs currently owned by target processes
        self._local_endpoints: set[tuple[str, int]] = set()
        self._pids: set[int] = set()
        self._sniffer = None
        self._writer = None
        self._stop = threading.Event()
        self._started = False
        self._packet_count = 0
        self._highlights: deque[dict] = deque(maxlen=500)
        self._log_path = Path(cfg.PACKET_LOG_FILE)
        self._pcap_path = Path(cfg.PACKET_PCAP_FILE)

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def highlights(self) -> list[dict]:
        return list(self._highlights)

    def update_process_endpoints(self, pids: set[int]) -> None:
        """Refresh local IP:port set from psutil for the given PIDs."""
        import psutil

        endpoints: set[tuple[str, int]] = set()
        alive: set[int] = set()
        for pid in pids:
            try:
                proc = psutil.Process(pid)
                alive.add(pid)
                for conn in proc.net_connections(kind="inet"):
                    if conn.laddr:
                        endpoints.add((conn.laddr.ip, int(conn.laddr.port)))
            except (psutil.Error, OSError):
                continue
        with self._lock:
            self._local_endpoints = endpoints
            self._pids = alive

    def _matches_process(self, src_ip: str, src_port: int | None, dst_ip: str, dst_port: int | None) -> bool:
        with self._lock:
            eps = self._local_endpoints
        if not eps:
            return False
        if src_port is not None and (src_ip, src_port) in eps:
            return True
        if dst_port is not None and (dst_ip, dst_port) in eps:
            return True
        # IPv4-mapped / wildcard looseness: match port alone if unique enough
        if cfg.PACKET_MATCH_PORT_ONLY:
            ports = {p for _, p in eps}
            if src_port in ports or dst_port in ports:
                return True
        return False

    def start(self) -> bool:
        if not cfg.ENABLE_PACKET_CAPTURE:
            return False
        if self._started:
            return True
        if not self._ensure_scapy():
            return False

        cfg.LOG_DIR.mkdir(parents=True, exist_ok=True)
        try:
            from scapy.all import AsyncSniffer, PcapWriter  # type: ignore

            self._writer = PcapWriter(str(self._pcap_path), append=True, sync=True)
        except Exception as exc:
            self.bus.emit(BehaviorEvent(
                category="system",
                action="pcap_writer_failed",
                summary=f"PCAP writer failed: {exc}",
                interesting=True,
            ))
            self._writer = None

        try:
            from scapy.all import AsyncSniffer  # type: ignore

            kwargs = {
                "prn": self._handle_packet,
                "store": False,
                "filter": cfg.PACKET_BPF_FILTER or None,
            }
            if cfg.PACKET_INTERFACE:
                kwargs["iface"] = cfg.PACKET_INTERFACE
            sniffer = AsyncSniffer(**{k: v for k, v in kwargs.items() if v is not None})
            sniffer.start()
            self._sniffer = sniffer
            self._started = True
            self.bus.emit(BehaviorEvent(
                category="system",
                action="packet_capture_started",
                summary=(
                    f"Packet capture started → {self._log_path.name}, {self._pcap_path.name}"
                ),
                details={
                    "log": str(self._log_path.resolve()),
                    "pcap": str(self._pcap_path.resolve()),
                    "bpf": cfg.PACKET_BPF_FILTER,
                },
                interesting=True,
            ))
            return True
        except Exception as exc:
            self.bus.emit(BehaviorEvent(
                category="system",
                action="packet_capture_failed",
                summary=(
                    f"Packet capture failed: {exc}. "
                    "Install Npcap (https://npcap.com/) and run as Administrator."
                ),
                interesting=True,
            ))
            return False

    def _ensure_scapy(self) -> bool:
        try:
            import scapy  # noqa: F401
            return True
        except ImportError:
            self.bus.emit(BehaviorEvent(
                category="system",
                action="scapy_missing",
                summary=(
                    "scapy not installed. Run: pip install scapy  "
                    "and install Npcap from https://npcap.com/"
                ),
                interesting=True,
            ))
            return False

    def _handle_packet(self, pkt) -> None:
        if self._stop.is_set():
            return
        try:
            record = self._analyze_packet(pkt)
            if record is None:
                return
            self._packet_count += 1
            self._append_log(record)
            if self._writer is not None:
                try:
                    self._writer.write(pkt)
                except Exception:
                    pass

            if record.get("highlights"):
                self._highlights.append(record)
                self.bus.emit(BehaviorEvent(
                    category="packet",
                    action="packet_interesting",
                    summary=record["summary"],
                    details=record,
                    interesting=True,
                ))
            elif cfg.PACKET_EMIT_ALL_EVENTS:
                self.bus.emit(BehaviorEvent(
                    category="packet",
                    action="packet",
                    summary=record["summary"],
                    details={k: record[k] for k in record if k != "payload"},
                    interesting=False,
                ))

            if self.on_packet:
                self.on_packet(record)
        except Exception:
            return

    def _analyze_packet(self, pkt) -> dict[str, Any] | None:
        try:
            from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS  # type: ignore
        except Exception:
            return None

        src_ip = dst_ip = ""
        src_port = dst_port = None
        proto = "OTHER"
        size = len(pkt)
        tcp_flags: list[str] = []
        payload = b""

        if pkt.haslayer(IP):
            ip = pkt[IP]
            src_ip, dst_ip = ip.src, ip.dst
        elif pkt.haslayer(IPv6):
            ip = pkt[IPv6]
            src_ip, dst_ip = ip.src, ip.dst
        else:
            return None

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port, dst_port = int(tcp.sport), int(tcp.dport)
            proto = "TCP"
            tcp_flags = _tcp_flags(tcp)
            payload = bytes(tcp.payload) if tcp.payload else b""
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port, dst_port = int(udp.sport), int(udp.dport)
            proto = "UDP"
            payload = bytes(udp.payload) if udp.payload else b""
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            payload = bytes(pkt[ICMP].payload) if pkt[ICMP].payload else b""
        else:
            payload = bytes(pkt.payload) if pkt.payload else b""

        if not self._matches_process(src_ip, src_port, dst_ip, dst_port):
            return None

        parsed: dict[str, Any] = {}
        app_proto = proto
        highlights: list[str] = []

        # DNS
        dns_info = _parse_dns(pkt)
        if dns_info:
            app_proto = "DNS"
            parsed["dns"] = dns_info
            highlights.append("dns_request" if dns_info.get("qr") == 0 else "dns_response")

        # HTTP
        http_info = _parse_http(payload)
        if http_info:
            app_proto = "HTTP"
            parsed["http"] = http_info
            highlights.append("http_request")
            if http_info.get("host"):
                highlights.append(f"http_host:{http_info['host']}")

        # TLS / SNI
        sni = _extract_sni_from_clienthello(payload)
        if sni:
            app_proto = "TLS"
            parsed["tls_sni"] = sni
            highlights.append(f"tls_sni:{sni}")
            highlights.append("https_clienthello")

        # Suspicious ports
        for port in (src_port, dst_port):
            if port in cfg.INTERESTING_PORTS and port not in (80, 443):
                highlights.append(f"interesting_port:{port}")
            if port in cfg.PACKET_SUSPICIOUS_PORTS:
                highlights.append(f"suspicious_port:{port}")

        # Exfiltration heuristic: large outbound payload from local endpoint
        with self._lock:
            local_eps = self._local_endpoints
        outbound = (src_ip, src_port) in local_eps if src_port is not None else False
        if outbound and len(payload) >= cfg.PACKET_EXFIL_PAYLOAD_BYTES:
            highlights.append("possible_data_exfil")
            parsed["exfil_bytes"] = len(payload)

        views = _payload_views(payload)
        ts = now_ts()
        direction = "outbound" if outbound else "inbound"
        summary = (
            f"{app_proto} {src_ip}:{src_port or '*'} → {dst_ip}:{dst_port or '*'} "
            f"size={size} {direction}"
        )
        if sni:
            summary += f" SNI={sni}"
        elif http_info and http_info.get("host"):
            summary += f" Host={http_info['host']}"
        elif dns_info and dns_info.get("qname"):
            summary += f" q={dns_info['qname']}"

        return {
            "timestamp": ts,
            "protocol": app_proto,
            "transport": proto,
            "src": f"{src_ip}:{src_port or '*'}",
            "dst": f"{dst_ip}:{dst_port or '*'}",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "size": size,
            "tcp_flags": tcp_flags,
            "direction": direction,
            "payload_len": len(payload),
            "payload": views,
            "parsed": parsed,
            "highlights": highlights,
            "summary": summary,
            "pids": sorted(self._pids),
        }

    def _append_log(self, record: dict[str, Any]) -> None:
        try:
            flags = ",".join(record.get("tcp_flags") or []) or "-"
            hl = ",".join(record.get("highlights") or []) or "-"
            payload = record.get("payload") or {}
            line = (
                f"[{record['timestamp']}]  {record['protocol']:<5}  "
                f"{record['src']}  →  {record['dst']}  "
                f"size={record['size']:<5}  flags={flags:<12}  "
                f"dir={record['direction']:<8}  highlights={hl}\n"
                f"    ASCII: {payload.get('ascii', '')}\n"
                f"    HEX  : {payload.get('hex', '')}\n"
            )
            if record.get("parsed"):
                line += f"    PARSE: {record['parsed']}\n"
            with self._log_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass

    def stop(self) -> None:
        self._stop.set()
        sniffer = self._sniffer
        if sniffer is not None and hasattr(sniffer, "stop"):
            try:
                sniffer.stop()
            except Exception:
                pass
        self._sniffer = None
        if self._writer is not None:
            try:
                self._writer.close()
            except Exception:
                pass
            self._writer = None
        if self._started:
            self.bus.emit(BehaviorEvent(
                category="system",
                action="packet_capture_stopped",
                summary=f"Packet capture stopped ({self._packet_count} packets kept)",
                details={"packets": self._packet_count},
            ))
        self._started = False
