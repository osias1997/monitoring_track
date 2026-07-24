"""Deep process inspection: modules, cmdline, env, children, resources."""

from __future__ import annotations

from typing import Any

import psutil

from .events import BehaviorEvent, EventBus


def _safe(fn, default=None):
    try:
        return fn()
    except (psutil.Error, OSError, PermissionError, AttributeError):
        return default


def inspect_process(pid: int) -> dict[str, Any]:
    """Collect a rich snapshot of a single process."""
    try:
        proc = psutil.Process(pid)
    except psutil.Error:
        return {"pid": pid, "error": "process_gone"}

    with proc.oneshot():
        info: dict[str, Any] = {
            "pid": pid,
            "name": _safe(proc.name, "?"),
            "exe": _safe(proc.exe),
            "cwd": _safe(proc.cwd),
            "cmdline": _safe(proc.cmdline, []),
            "username": _safe(proc.username),
            "create_time": _safe(proc.create_time),
            "status": _safe(proc.status),
            "num_threads": _safe(proc.num_threads),
            "cpu_percent": _safe(lambda: proc.cpu_percent(interval=0.0), 0.0),
            "memory_rss": _safe(lambda: proc.memory_info().rss),
            "memory_vms": _safe(lambda: proc.memory_info().vms),
        }

    # Environment (can be large / sensitive — truncated)
    environ = _safe(proc.environ, {}) or {}
    if isinstance(environ, dict):
        keys_of_interest = [
            k for k in environ
            if any(t in k.upper() for t in ("PROXY", "HTTP", "PATH", "TEMP", "USER", "API", "TOKEN", "KEY"))
        ]
        info["environ_interesting"] = {k: environ[k] for k in keys_of_interest[:40]}
        info["environ_count"] = len(environ)
    else:
        info["environ_interesting"] = {}
        info["environ_count"] = 0

    # Loaded modules / mapped files (DLL-ish)
    modules: list[str] = []
    maps = _safe(proc.memory_maps, []) or []
    seen = set()
    for m in maps:
        path = getattr(m, "path", None) or ""
        if not path or path in seen:
            continue
        seen.add(path)
        lower = path.lower()
        if lower.endswith((".dll", ".ocx", ".sys", ".exe")) or "\\" in path:
            modules.append(path)
    info["modules"] = modules[:300]
    info["module_count"] = len(modules)

    # Children
    children = []
    for child in _safe(proc.children, []) or []:
        children.append({
            "pid": child.pid,
            "name": _safe(child.name, "?"),
            "cmdline": _safe(child.cmdline, []),
        })
    info["children"] = children

    # Open files snapshot
    open_files = []
    for f in _safe(proc.open_files, []) or []:
        open_files.append({"path": f.path, "fd": getattr(f, "fd", None)})
    info["open_files"] = open_files[:200]

    return info


class ProcessTracker:
    """Track resource spikes and new child processes across polls."""

    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._known_children: dict[int, set[int]] = {}
        self._last_cpu: dict[int, float] = {}
        self._last_mem: dict[int, int] = {}
        self._last_threads: dict[int, int] = {}
        self._known_modules: dict[int, set[str]] = {}

    def poll(self, pid: int, process_name: str) -> dict[str, Any]:
        snap = inspect_process(pid)
        if snap.get("error"):
            return snap

        # New children
        child_pids = {c["pid"] for c in snap.get("children", [])}
        prev = self._known_children.get(pid, set())
        for c in snap.get("children", []):
            if c["pid"] not in prev:
                self.bus.emit(BehaviorEvent(
                    category="process",
                    action="child_created",
                    summary=f"Child process spawned: {c['name']} (PID {c['pid']})",
                    pid=pid,
                    process=process_name,
                    details=c,
                    interesting=True,
                ))
        self._known_children[pid] = child_pids

        # New modules
        mods = set(snap.get("modules", []))
        prev_mods = self._known_modules.get(pid)
        if prev_mods is not None:
            for m in sorted(mods - prev_mods):
                unusual = self._unusual_dll(m)
                self.bus.emit(BehaviorEvent(
                    category="process",
                    action="module_loaded",
                    summary=f"Module loaded: {m}",
                    pid=pid,
                    process=process_name,
                    details={"path": m, "unusual": unusual},
                    interesting=unusual,
                ))
        self._known_modules[pid] = mods

        # Resource spikes
        cpu = float(snap.get("cpu_percent") or 0.0)
        mem = int(snap.get("memory_rss") or 0)
        threads = int(snap.get("num_threads") or 0)
        prev_cpu = self._last_cpu.get(pid, cpu)
        prev_mem = self._last_mem.get(pid, mem)
        prev_thr = self._last_threads.get(pid, threads)

        if cpu - prev_cpu >= 25.0:
            self.bus.emit(BehaviorEvent(
                category="process",
                action="cpu_spike",
                summary=f"CPU spike {prev_cpu:.1f}% → {cpu:.1f}%",
                pid=pid,
                process=process_name,
                details={"from": prev_cpu, "to": cpu},
                interesting=True,
            ))
        if prev_mem and mem > prev_mem * 1.35 and (mem - prev_mem) > 20 * 1024 * 1024:
            self.bus.emit(BehaviorEvent(
                category="process",
                action="memory_spike",
                summary=f"Memory spike {prev_mem} → {mem} bytes",
                pid=pid,
                process=process_name,
                details={"from": prev_mem, "to": mem},
                interesting=True,
            ))
        if threads - prev_thr >= 8:
            self.bus.emit(BehaviorEvent(
                category="process",
                action="thread_spike",
                summary=f"Thread count {prev_thr} → {threads}",
                pid=pid,
                process=process_name,
                details={"from": prev_thr, "to": threads},
                interesting=True,
            ))

        self._last_cpu[pid] = cpu
        self._last_mem[pid] = mem
        self._last_threads[pid] = threads
        return snap

    @staticmethod
    def _unusual_dll(path: str) -> bool:
        lower = path.lower()
        common = ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\winsxs\\")
        if any(c in lower for c in common):
            return False
        # Temp / user-writable locations are more interesting
        return any(x in lower for x in ("\\temp\\", "\\appdata\\", "\\downloads\\", "\\users\\public\\"))
