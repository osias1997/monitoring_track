"""Optional Frida / ETW helpers — enabled only when configured and available."""

from __future__ import annotations

from .events import BehaviorEvent, EventBus


def try_start_frida(bus: EventBus, pid: int) -> bool:
    """Attach Frida and hook common network APIs (best-effort, optional)."""
    import behavior_config as cfg
    if not cfg.ENABLE_FRIDA_HOOKS:
        return False
    try:
        import frida  # type: ignore
    except ImportError:
        bus.emit(BehaviorEvent(
            category="system",
            action="frida_missing",
            summary="frida not installed — API hooking disabled",
        ))
        return False

    js = """
    // Minimal connect() probe — extend as needed
    var connect = Module.findExportByName('ws2_32.dll', 'connect');
    if (connect) {
      Interceptor.attach(connect, {
        onEnter: function (args) {
          send({hook: 'connect', pid: Process.id});
        }
      });
    }
    """

    try:
        session = frida.attach(pid)
        script = session.create_script(js)

        def on_message(message, data):
            bus.emit(BehaviorEvent(
                category="process",
                action="frida_hook",
                summary=f"Frida hook: {message}",
                pid=pid,
                details={"message": message},
                interesting=True,
            ))

        script.on("message", on_message)
        script.load()
        bus.emit(BehaviorEvent(
            category="system",
            action="frida_attached",
            summary=f"Frida attached to PID {pid}",
            pid=pid,
            interesting=True,
        ))
        return True
    except Exception as exc:
        bus.emit(BehaviorEvent(
            category="system",
            action="frida_failed",
            summary=f"Frida attach failed: {exc}",
            pid=pid,
        ))
        return False


def try_etw_note(bus: EventBus) -> None:
    """Document ETW capability; full ETW needs pywintrace / specialized tooling."""
    import behavior_config as cfg
    if not cfg.ENABLE_ETW_TRACE:
        return
    bus.emit(BehaviorEvent(
        category="system",
        action="etw_note",
        summary=(
            "ETW tracing flag enabled — use Microsoft Message Analyzer / "
            "procmon / pywintrace for full kernel callbacks; not embedded here."
        ),
        interesting=False,
    ))
