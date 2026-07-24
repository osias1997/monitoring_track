"""
Frida API hooking for Winsock / WinHTTP / WinINet.

Install:
  pip install frida frida-tools

Attach to each monitored PID and stream hook events into the EventBus.
Sessions are kept alive for the duration of the analyzer run.

Tool made by Osidev
"""

from __future__ import annotations

from typing import Any

import behavior_config as cfg
from .events import BehaviorEvent, EventBus

# Durable Frida JS — hooks common outbound network APIs.
FRIDA_SCRIPT = r"""
'use strict';

function ptrMsg(tag, fields) {
  send(Object.assign({hook: tag}, fields || {}));
}

function readAnsi(p) {
  try { return p.isNull() ? null : Memory.readAnsiString(p); } catch (e) { return null; }
}
function readUtf16(p) {
  try { return p.isNull() ? null : Memory.readUtf16String(p); } catch (e) { return null; }
}

function hookExport(mod, name, callbacks) {
  var addr = Module.findExportByName(mod, name);
  if (!addr) return false;
  Interceptor.attach(addr, callbacks);
  return true;
}

// ---- Winsock ----
if (%HOOK_WINSOCK%) {
  hookExport('ws2_32.dll', 'connect', {
    onEnter: function (args) {
      this.sock = args[0];
      try {
        var sa = args[1];
        var family = Memory.readU16(sa);
        if (family === 2) { // AF_INET
          var port = (Memory.readU8(sa.add(2)) << 8) | Memory.readU8(sa.add(3));
          var ip = Memory.readU8(sa.add(4)) + '.' + Memory.readU8(sa.add(5)) + '.' +
                   Memory.readU8(sa.add(6)) + '.' + Memory.readU8(sa.add(7));
          ptrMsg('winsock_connect', {ip: ip, port: port});
        } else {
          ptrMsg('winsock_connect', {family: family});
        }
      } catch (e) {
        ptrMsg('winsock_connect', {error: e.message});
      }
    }
  });

  hookExport('ws2_32.dll', 'send', {
    onEnter: function (args) {
      var len = args[2].toInt32();
      ptrMsg('winsock_send', {len: len});
    }
  });

  hookExport('ws2_32.dll', 'recv', {
    onEnter: function (args) { this.buf = args[1]; this.len = args[2].toInt32(); },
    onLeave: function (retval) {
      var n = retval.toInt32();
      if (n > 0) ptrMsg('winsock_recv', {len: n});
    }
  });
}

// ---- WinHTTP ----
if (%HOOK_WINHTTP%) {
  hookExport('winhttp.dll', 'WinHttpConnect', {
    onEnter: function (args) {
      ptrMsg('winhttp_connect', {server: readUtf16(args[1]), port: args[2].toInt32()});
    }
  });
  hookExport('winhttp.dll', 'WinHttpOpenRequest', {
    onEnter: function (args) {
      ptrMsg('winhttp_open_request', {
        verb: readUtf16(args[1]),
        path: readUtf16(args[2])
      });
    }
  });
  hookExport('winhttp.dll', 'WinHttpSendRequest', {
    onEnter: function (args) {
      ptrMsg('winhttp_send_request', {
        headers: readUtf16(args[1]),
        optional_len: args[4].toInt32()
      });
    }
  });
}

// ---- WinINet ----
if (%HOOK_WININET%) {
  hookExport('wininet.dll', 'InternetConnectW', {
    onEnter: function (args) {
      ptrMsg('wininet_connect', {server: readUtf16(args[1]), port: args[2].toInt32()});
    }
  });
  hookExport('wininet.dll', 'HttpOpenRequestW', {
    onEnter: function (args) {
      ptrMsg('wininet_open_request', {verb: readUtf16(args[1]), path: readUtf16(args[2])});
    }
  });
  hookExport('wininet.dll', 'HttpSendRequestW', {
    onEnter: function (args) {
      ptrMsg('wininet_send_request', {headers: readUtf16(args[1])});
    }
  });
}

ptrMsg('frida_ready', {pid: Process.id});
"""


class FridaManager:
    """Attach Frida scripts to monitored PIDs and forward messages to EventBus."""

    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._sessions: dict[int, Any] = {}
        self._scripts: dict[int, Any] = {}

    def _build_script(self) -> str:
        return (
            FRIDA_SCRIPT
            .replace("%HOOK_WINSOCK%", "true" if cfg.FRIDA_HOOK_WINSOCK else "false")
            .replace("%HOOK_WINHTTP%", "true" if cfg.FRIDA_HOOK_WINHTTP else "false")
            .replace("%HOOK_WININET%", "true" if cfg.FRIDA_HOOK_WININET else "false")
        )

    def attach(self, pid: int, process_name: str | None = None) -> bool:
        if not cfg.ENABLE_FRIDA_HOOKS:
            return False
        if pid in self._sessions:
            return True
        try:
            import frida  # type: ignore
        except ImportError:
            self.bus.emit(BehaviorEvent(
                category="system",
                action="frida_missing",
                summary="frida not installed — run: pip install frida frida-tools",
                interesting=True,
            ))
            return False

        try:
            session = frida.attach(pid)
            script = session.create_script(self._build_script())

            def on_message(message, data):
                payload = message.get("payload") if isinstance(message, dict) else message
                if not isinstance(payload, dict):
                    payload = {"raw": payload}
                hook = payload.get("hook", "frida")
                summary_bits = [f"Frida {hook}"]
                for k in ("ip", "port", "server", "path", "verb", "len"):
                    if k in payload and payload[k] is not None:
                        summary_bits.append(f"{k}={payload[k]}")
                self.bus.emit(BehaviorEvent(
                    category="frida",
                    action=f"frida_{hook}",
                    summary=" ".join(summary_bits),
                    pid=pid,
                    process=process_name,
                    details=payload,
                    interesting=True,
                ))

            script.on("message", on_message)
            script.load()
            self._sessions[pid] = session
            self._scripts[pid] = script
            self.bus.emit(BehaviorEvent(
                category="system",
                action="frida_attached",
                summary=f"Frida attached to PID {pid} (Winsock/WinHTTP/WinINet)",
                pid=pid,
                process=process_name,
                interesting=True,
            ))
            return True
        except Exception as exc:
            self.bus.emit(BehaviorEvent(
                category="system",
                action="frida_failed",
                summary=f"Frida attach failed for PID {pid}: {exc}",
                pid=pid,
                interesting=True,
            ))
            return False

    def detach_all(self) -> None:
        for pid, script in list(self._scripts.items()):
            try:
                script.unload()
            except Exception:
                pass
        for pid, session in list(self._sessions.items()):
            try:
                session.detach()
            except Exception:
                pass
        self._scripts.clear()
        self._sessions.clear()


# Back-compat wrappers used by older analyzer paths
def try_start_frida(bus: EventBus, pid: int) -> bool:
    # Stateless one-shot — prefer FridaManager in the analyzer
    mgr = FridaManager(bus)
    return mgr.attach(pid)


def try_etw_note(bus: EventBus) -> None:
    """Deprecated stub — EtwTracer replaces this."""
    if cfg.ENABLE_ETW_TRACE:
        bus.emit(BehaviorEvent(
            category="system",
            action="etw_note",
            summary="ETW enabled — starting EtwTracer module",
        ))
