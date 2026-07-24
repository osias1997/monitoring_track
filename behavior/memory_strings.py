"""Optional memory strings scan for URLs, domains, and key-like tokens."""

from __future__ import annotations

import ctypes
import re
import sys
from typing import Any

import behavior_config as cfg
from .events import BehaviorEvent, EventBus

_URL_RE = re.compile(rb"https?://[^\x00-\x1f\x7f]{4,200}", re.I)
_DOMAIN_RE = re.compile(rb"\b(?:[a-z0-9-]{2,}\.)+(?:com|net|org|io|dev|app|ru|cn|info|xyz)\b", re.I)
_KEY_RE = re.compile(rb"(?i)(api[_-]?key|secret|token|bearer|authorization)[=:\"'\s]{1,6}([a-z0-9\-_.]{8,80})")


def _scan_process_strings(pid: int) -> dict[str, list[str]]:
    """Best-effort ReadProcessMemory string harvest (Windows + admin recommended)."""
    found = {"urls": [], "domains": [], "secrets": []}
    if sys.platform != "win32" or not cfg.ENABLE_MEMORY_STRINGS:
        return found

    try:
        import psutil
        proc = psutil.Process(pid)
        maps = proc.memory_maps(grouped=False)
    except Exception:
        return found

    kernel32 = ctypes.windll.kernel32
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return found

    try:
        buf = ctypes.create_string_buffer(cfg.MEMORY_MAX_BYTES_PER_REGION)
        read = ctypes.c_size_t(0)
        scanned = 0
        for m in maps:
            if scanned >= cfg.MEMORY_MAX_REGIONS:
                break
            path = getattr(m, "path", "") or ""
            # Prefer anonymous / heap-like regions when path empty
            addr_str = getattr(m, "addr", None)
            if not addr_str or "-" not in str(addr_str):
                continue
            try:
                start_s, end_s = str(addr_str).split("-", 1)
                start = int(start_s, 16)
                end = int(end_s, 16)
            except ValueError:
                continue
            size = min(end - start, cfg.MEMORY_MAX_BYTES_PER_REGION)
            if size <= 0:
                continue
            ok = kernel32.ReadProcessMemory(
                handle,
                ctypes.c_void_p(start),
                buf,
                size,
                ctypes.byref(read),
            )
            if not ok or read.value <= 0:
                continue
            data = buf.raw[: read.value]
            scanned += 1
            for murl in _URL_RE.findall(data):
                s = murl.decode("utf-8", errors="ignore")
                if s not in found["urls"]:
                    found["urls"].append(s)
            for md in _DOMAIN_RE.findall(data):
                s = md.decode("utf-8", errors="ignore")
                if s not in found["domains"]:
                    found["domains"].append(s)
            for mk in _KEY_RE.findall(data):
                s = (mk[0] + "=" + mk[1][:6] + "…").decode("utf-8", errors="ignore")
                if s not in found["secrets"]:
                    found["secrets"].append(s)
            if len(found["urls"]) + len(found["domains"]) > 80:
                break
    finally:
        kernel32.CloseHandle(handle)

    for k in found:
        found[k] = found[k][:40]
    return found


def maybe_memory_snapshot(bus: EventBus, pid: int, process_name: str, session_id: str) -> None:
    if not cfg.ENABLE_MEMORY_STRINGS:
        return
    result = _scan_process_strings(pid)
    total = sum(len(v) for v in result.values())
    bus.emit(BehaviorEvent(
        category="memory",
        action="strings_snapshot",
        summary=f"Memory strings snapshot ({total} hits)",
        pid=pid,
        process=process_name,
        details=result,
        interesting=total > 0,
        session_id=session_id,
    ))
