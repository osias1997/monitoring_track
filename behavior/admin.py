"""Admin rights detection and optional UAC elevation on Windows."""

from __future__ import annotations

import ctypes
import sys


def is_admin() -> bool:
    if sys.platform != "win32":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_elevated() -> bool:
    """Relaunch the current script with a UAC elevation prompt. Returns True if launched."""
    if sys.platform != "win32":
        return False
    try:
        params = " ".join(f'"{a}"' if " " in a else a for a in sys.argv)
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        return int(rc) > 32
    except Exception:
        return False


def ensure_admin_warning(offer_elevation: bool = True) -> None:
    if is_admin():
        return
    print(
        "\n[!] WARNING: Not running as Administrator.\n"
        "    Some processes hide sockets, modules, files, and memory without elevation.\n"
    )
    if not offer_elevation:
        return
    try:
        answer = input("Relaunch elevated now? [y/N]: ").strip().lower()
    except EOFError:
        return
    if answer in {"y", "yes"}:
        if relaunch_elevated():
            sys.exit(0)
        print("[!] Elevation failed or was cancelled.")
