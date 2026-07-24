"""
Strong event correlation engine.

Groups related activities into behavior sessions using:
  - shared PID
  - shared remote IP / hostname / DNS query
  - temporal proximity (CORRELATION_WINDOW_SEC)
  - causal hints (DNS → connect, file/registry → network, Frida → connect)

Tool made by Osidev
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import behavior_config as cfg
from .events import BehaviorEvent
from .highlights import score_session


@dataclass
class BehaviorSession:
    session_id: str
    seed_summary: str
    pid: int | None = None
    process: str | None = None
    remote_ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    events: list[BehaviorEvent] = field(default_factory=list)
    start_epoch: float = 0.0
    end_epoch: float = 0.0
    tags: set[str] = field(default_factory=set)

    def add(self, event: BehaviorEvent) -> None:
        self.events.append(event)
        event.session_id = self.session_id
        self.end_epoch = max(self.end_epoch, event.epoch)
        if event.pid and not self.pid:
            self.pid = event.pid
        if event.process and not self.process:
            self.process = event.process
        self._ingest_details(event)

    def _ingest_details(self, event: BehaviorEvent) -> None:
        d = event.details or {}
        for key in ("remote_ip", "dst_ip", "src_ip", "ip"):
            val = d.get(key)
            if val:
                self.remote_ips.add(str(val))
        for key in ("hostname", "tls_sni", "qname", "server", "host"):
            val = d.get(key)
            if isinstance(val, str) and val:
                self.domains.add(val.lower())
        http = d.get("http") or {}
        if isinstance(http, dict) and http.get("host"):
            self.domains.add(str(http["host"]).lower())
        parsed = d.get("parsed") or {}
        if isinstance(parsed, dict):
            if parsed.get("tls_sni"):
                self.domains.add(str(parsed["tls_sni"]).lower())
            dns = parsed.get("dns") or {}
            if isinstance(dns, dict) and dns.get("qname"):
                self.domains.add(str(dns["qname"]).lower())
        if event.category in {"etw", "frida", "packet", "memory"}:
            self.tags.add(event.category)
        if event.interesting:
            self.tags.add("interesting")


class CorrelationEngine:
    """Assigns and maintains behavior sessions for an EventBus snapshot."""

    def __init__(self) -> None:
        self.sessions: dict[str, BehaviorSession] = {}
        self._open: list[BehaviorSession] = []

    def _new_session(self, event: BehaviorEvent) -> BehaviorSession:
        sid = f"sess-{uuid.uuid4().hex[:10]}"
        sess = BehaviorSession(
            session_id=sid,
            seed_summary=event.summary,
            pid=event.pid,
            process=event.process,
            start_epoch=event.epoch,
            end_epoch=event.epoch,
        )
        sess.add(event)
        self.sessions[sid] = sess
        self._open.append(sess)
        return sess

    def _compatible(self, sess: BehaviorSession, event: BehaviorEvent) -> bool:
        window = cfg.CORRELATION_WINDOW_SEC
        # DNS→connect gets a wider window
        if event.category == "network" and ("dns" in sess.tags or any(
            e.action.endswith("dns") or "dns" in e.action for e in sess.events[-8:]
        )):
            window = max(window, cfg.DNS_TO_CONNECT_WINDOW_SEC)

        if event.epoch - sess.end_epoch > window and abs(event.epoch - sess.start_epoch) > window:
            # allow if still within window of last event
            if event.epoch - sess.end_epoch > window:
                return False

        if event.pid and sess.pid and event.pid != sess.pid:
            # Different PID only OK for short-lived children tagged on same process name
            if event.process and sess.process and event.process.lower() == sess.process.lower():
                pass
            else:
                return False

        d = event.details or {}
        ips = {str(d[k]) for k in ("remote_ip", "dst_ip", "src_ip", "ip") if d.get(k)}
        domains = set()
        for key in ("hostname", "tls_sni", "qname", "server", "host"):
            if d.get(key):
                domains.add(str(d[key]).lower())
        http = d.get("http") or {}
        if isinstance(http, dict) and http.get("host"):
            domains.add(str(http["host"]).lower())

        # Strong links
        if ips and ips & sess.remote_ips:
            return True
        if domains and domains & sess.domains:
            return True
        if event.pid and sess.pid and event.pid == sess.pid:
            # Same process within time window
            if abs(event.epoch - sess.end_epoch) <= window:
                return True
        # Soft: interesting pre-network signals within window for same process name
        if event.process and sess.process and event.process.lower() == sess.process.lower():
            if abs(event.epoch - sess.end_epoch) <= window:
                return True
        return False

    def ingest(self, event: BehaviorEvent) -> BehaviorSession:
        # Skip pure system noise for new sessions unless interesting
        if event.category == "system" and not event.interesting:
            # Attach to latest open session of same pid if any
            for sess in reversed(self._open):
                if event.pid and sess.pid == event.pid and abs(event.epoch - sess.end_epoch) <= cfg.CORRELATION_WINDOW_SEC:
                    sess.add(event)
                    return sess
            return self._new_session(event)

        for sess in reversed(self._open[-40:]):
            if self._compatible(sess, event):
                sess.add(event)
                return sess
        return self._new_session(event)

    def rebuild(self, events: list[BehaviorEvent]) -> dict[str, BehaviorSession]:
        self.sessions.clear()
        self._open.clear()
        for event in sorted(events, key=lambda e: e.epoch):
            self.ingest(event)
        return self.sessions

    def scored_sessions(self) -> list[dict[str, Any]]:
        out = []
        for sess in self.sessions.values():
            score = score_session(sess.events)
            # Extra correlation-aware flags
            flags = list(score["flags"])
            cats = {e.category for e in sess.events}
            if "etw" in cats and "network" in cats:
                flags.append("etw_then_network")
            if "frida" in cats and "network" in cats:
                flags.append("api_hook_then_network")
            if sess.domains and any(e.category == "network" for e in sess.events):
                flags.append("domain_resolved_session")
            severity = score["severity"]
            if "api_hook_then_network" in flags or "etw_then_network" in flags:
                severity = "high" if severity != "high" and len(flags) >= 2 else severity
                if "api_hook_then_network" in flags:
                    severity = "high"
            out.append({
                "session_id": sess.session_id,
                "summary": sess.seed_summary,
                "pid": sess.pid,
                "process": sess.process,
                "remote_ips": sorted(sess.remote_ips),
                "domains": sorted(sess.domains),
                "tags": sorted(sess.tags),
                "event_count": len(sess.events),
                "start": sess.start_epoch,
                "end": sess.end_epoch,
                "flags": sorted(set(flags)),
                "severity": severity,
                "events": sess.events,
            })
        out.sort(key=lambda s: ({"high": 0, "medium": 1, "low": 2}.get(s["severity"], 3), -s["event_count"]))
        return out
