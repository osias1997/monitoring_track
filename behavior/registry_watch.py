"""Poll interesting Windows registry keys for changes."""

from __future__ import annotations

import sys
from typing import Any

import behavior_config as cfg
from .events import BehaviorEvent, EventBus

if sys.platform == "win32":
    import winreg
else:
    winreg = None  # type: ignore


_HIVE = {}
if winreg is not None:
    _HIVE = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}


def _read_key(hive_name: str, subkey: str) -> dict[str, Any] | None:
    if winreg is None:
        return None
    hive = _HIVE.get(hive_name)
    if hive is None:
        return None
    values: dict[str, Any] = {}
    try:
        with winreg.OpenKey(hive, subkey) as key:
            i = 0
            while True:
                try:
                    name, data, _rtype = winreg.EnumValue(key, i)
                    values[str(name)] = data if not isinstance(data, bytes) else data.hex()[:120]
                    i += 1
                except OSError:
                    break
    except OSError:
        return None
    return values


def _diff(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    changed = {}
    for k, v in new.items():
        if k not in old or old[k] != v:
            changed[k] = {"old": old.get(k), "new": v}
    for k in old:
        if k not in new:
            changed[k] = {"old": old[k], "new": None}
    return changed


class RegistryWatcher:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._snapshots: dict[str, dict[str, Any]] = {}

    def poll(self) -> None:
        if not cfg.ENABLE_REGISTRY_WATCH or winreg is None:
            return
        for subkey, hive_name in cfg.REGISTRY_KEYS:
            full = f"{hive_name}\\{subkey}"
            current = _read_key(hive_name, subkey)
            if current is None:
                continue
            prev = self._snapshots.get(full)
            self._snapshots[full] = current
            if prev is None:
                continue
            changes = _diff(prev, current)
            if not changes:
                continue
            networkish = any(
                t in (k.lower() + str(v).lower())
                for k, v in changes.items()
                for t in ("proxy", "http", "ftp", "auto", "dns", "dhcp", "enable")
            )
            self.bus.emit(BehaviorEvent(
                category="registry",
                action="reg_change",
                summary=f"Registry changed: {full}",
                details={"key": full, "changes": changes, "network_related": networkish},
                interesting=True,
            ))
