"""Backward-compatible exports — prefer behavior.frida_hooks / behavior.etw_trace. """

from __future__ import annotations

from .frida_hooks import FridaManager, try_etw_note, try_start_frida

__all__ = ["FridaManager", "try_start_frida", "try_etw_note"]
