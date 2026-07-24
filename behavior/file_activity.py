"""File activity via process open_files() polling + optional watchdog."""

from __future__ import annotations

import threading
import time
from pathlib import Path
import psutil

import behavior_config as cfg
from .events import BehaviorEvent, EventBus


def classify_file(path: str) -> list[str]:
    tags: list[str] = []
    lower = path.lower()
    suffix = Path(path).suffix.lower()
    if suffix in cfg.INTERESTING_FILE_SUFFIXES:
        tags.append("interesting_suffix")
    for token, tag in (
        ("cookie", "cookies"),
        ("cert", "certificate"),
        (".pem", "certificate"),
        (".pfx", "certificate"),
        ("login", "credentials"),
        ("password", "credentials"),
        ("proxy", "network_config"),
        ("config", "config"),
        (".db", "database"),
        ("sqlite", "database"),
    ):
        if token in lower:
            tags.append(tag)
    return sorted(set(tags))


class OpenFilesPoller:
    """Detect newly opened files by comparing psutil open_files() sets."""

    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._seen: dict[int, set[str]] = {}

    def poll(self, pid: int, process_name: str) -> list[str]:
        newly: list[str] = []
        try:
            proc = psutil.Process(pid)
            paths = {f.path for f in (proc.open_files() or [])}
        except (psutil.Error, OSError):
            return newly

        prev = self._seen.get(pid, set())
        for path in sorted(paths - prev):
            tags = classify_file(path)
            interesting = bool(tags)
            self.bus.emit(BehaviorEvent(
                category="file",
                action="file_open",
                summary=f"File opened: {path}",
                pid=pid,
                process=process_name,
                details={"path": path, "tags": tags},
                interesting=interesting,
            ))
            newly.append(path)
        self._seen[pid] = paths
        return newly


class DirectoryWatcher:
    """Best-effort FS watch using watchdog (not process-attributed)."""

    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._observer = None
        self._lock = threading.Lock()
        self._recent: list[dict] = []

    def start(self) -> bool:
        if not cfg.ENABLE_FILE_ACTIVITY:
            return False
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except ImportError:
            self.bus.emit(BehaviorEvent(
                category="system",
                action="watchdog_missing",
                summary="watchdog not installed — directory watching disabled",
                details={},
            ))
            return False

        bus = self.bus
        recent = self._recent
        lock = self._lock

        class Handler(FileSystemEventHandler):
            def on_any_event(self, event):
                if getattr(event, "is_directory", False):
                    return
                path = getattr(event, "dest_path", None) or event.src_path
                tags = classify_file(path)
                rec = {
                    "epoch": time.time(),
                    "path": path,
                    "event_type": event.event_type,
                    "tags": tags,
                }
                with lock:
                    recent.append(rec)
                    if len(recent) > 500:
                        del recent[:250]
                bus.emit(BehaviorEvent(
                    category="file",
                    action=f"fs_{event.event_type}",
                    summary=f"FS {event.event_type}: {path}",
                    details=rec,
                    interesting=bool(tags),
                ))

        observer = Observer()
        handler = Handler()
        started_any = False
        for d in cfg.WATCH_DIRS:
            p = Path(d)
            if not p.exists():
                continue
            try:
                observer.schedule(handler, str(p), recursive=True)
                started_any = True
            except OSError:
                continue
        if not started_any:
            return False
        observer.daemon = True
        observer.start()
        self._observer = observer
        return True

    def recent_around(self, epoch: float, window: float = 2.0) -> list[dict]:
        with self._lock:
            return [r for r in self._recent if abs(r["epoch"] - epoch) <= window]

    def stop(self) -> None:
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=2)
            self._observer = None
