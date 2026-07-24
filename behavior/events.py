"""High-precision event model and session sequence store."""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import behavior_config as cfg


def now_ts() -> str:
    if cfg.HIGH_PRECISION_TIMESTAMPS:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def now_epoch() -> float:
    return time.time()


@dataclass
class BehaviorEvent:
    category: str          # network | process | file | registry | dns | memory | system
    action: str            # e.g. connection_new, dll_loaded, file_open, reg_change
    summary: str
    pid: int | None = None
    process: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    interesting: bool = False
    timestamp: str = field(default_factory=now_ts)
    epoch: float = field(default_factory=now_epoch)
    session_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EventBus:
    """Thread-safe event collector with per-connection session grouping."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.events: deque[BehaviorEvent] = deque(maxlen=cfg.KEEP_LAST_N_EVENTS_IN_MEMORY)
        self.sessions: dict[str, list[BehaviorEvent]] = defaultdict(list)
        self._log_path = cfg.SESSION_EVENT_LOG
        cfg.LOG_DIR.mkdir(parents=True, exist_ok=True)
        # Rolling window of recent events for "before connection" context
        self._recent: deque[BehaviorEvent] = deque(maxlen=200)

    def emit(self, event: BehaviorEvent) -> BehaviorEvent:
        with self._lock:
            self.events.append(event)
            self._recent.append(event)
            if event.session_id:
                self.sessions[event.session_id].append(event)
            self._append_jsonl(event)
        return event

    def _append_jsonl(self, event: BehaviorEvent) -> None:
        try:
            with self._log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
        except OSError:
            pass

    def recent_before(self, epoch: float, seconds: float = 3.0) -> list[BehaviorEvent]:
        with self._lock:
            return [e for e in list(self._recent) if epoch - seconds <= e.epoch < epoch]

    def snapshot(self) -> list[BehaviorEvent]:
        with self._lock:
            return list(self.events)

    def session_map(self) -> dict[str, list[BehaviorEvent]]:
        with self._lock:
            return {k: list(v) for k, v in self.sessions.items()}
