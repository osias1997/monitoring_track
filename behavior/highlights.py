"""Heuristic highlighting of interesting / suspicious behaviors."""

from __future__ import annotations

from typing import Any

import behavior_config as cfg
from .events import BehaviorEvent


def annotate_connection(details: dict[str, Any]) -> list[str]:
    flags: list[str] = []
    host = (details.get("hostname") or details.get("remote_ip") or "").lower()
    port = details.get("remote_port")
    remote = (details.get("remote") or "").lower()

    if port in cfg.INTERESTING_PORTS:
        flags.append(f"interesting_port:{port}")
    for hint in cfg.SUSPICIOUS_REMOTE_HINTS:
        if hint in host or hint in remote:
            flags.append(f"suspicious_host_hint:{hint}")
    if details.get("direction") == "outbound" and port not in (80, 443, 8080, 8443, 53):
        flags.append("uncommon_outbound_port")
    if details.get("likely_dns"):
        flags.append("dns_channel")
    return flags


def score_session(events: list[BehaviorEvent]) -> dict[str, Any]:
    flags: list[str] = []
    categories = {e.category for e in events}
    interesting = [e for e in events if e.interesting]

    if "registry" in categories and "network" in categories:
        flags.append("registry_then_network")
    if "file" in categories and "network" in categories:
        file_tags = []
        for e in events:
            if e.category == "file":
                file_tags.extend(e.details.get("tags") or [])
        if any(t in file_tags for t in ("cookies", "credentials", "certificate", "database")):
            flags.append("sensitive_file_then_network")
    if any(e.action == "child_created" for e in events):
        flags.append("spawned_child_near_network")
    if any(e.action == "module_loaded" and e.interesting for e in events):
        flags.append("unusual_dll_near_network")
    if any(e.category == "memory" and (e.details.get("secrets") or e.details.get("urls")) for e in events):
        flags.append("memory_iocs")

    # Packet-capture driven signals
    packet_events = [e for e in events if e.category == "packet"]
    if any("dns_request" in (e.details.get("highlights") or []) for e in packet_events):
        flags.append("dns_from_packets")
    if any(
        any(str(h).startswith("tls_sni:") or str(h).startswith("http_host:") for h in (e.details.get("highlights") or []))
        for e in packet_events
    ):
        flags.append("http_https_from_packets")
    if any("possible_data_exfil" in (e.details.get("highlights") or []) for e in packet_events):
        flags.append("possible_data_exfil")
    if any(
        any(str(h).startswith("suspicious_port:") for h in (e.details.get("highlights") or []))
        for e in packet_events
    ):
        flags.append("suspicious_port_traffic")

    severity = "low"
    if len(flags) >= 2 or len(interesting) >= 4:
        severity = "medium"
    if (
        "possible_data_exfil" in flags
        or "sensitive_file_then_network" in flags
        or "suspicious_port_traffic" in flags
        or any(f.startswith("suspicious_host_hint") for f in flags)
    ):
        severity = "high"

    return {"flags": flags, "severity": severity, "interesting_events": len(interesting)}
