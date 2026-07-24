#!/usr/bin/env python3
"""
Osidev live web dashboard — now powered by Behavior Analyzer v2.

Runs the same deep monitoring stack as behavior_analyzer.py:
  process / DLL signatures / files / registry / DNS / packets / ETW / Frida / memory
  + correlation sessions + professional report generation from the browser.

Install:
  pip install -r requirements.txt
  # Npcap for packets: https://npcap.com/
  # Optional: pip install frida frida-tools

Run (Administrator recommended):
  python web_dashboard.py
  → http://127.0.0.1:5050

Tool made by Osidev
"""

from __future__ import annotations

import csv
import io
import json
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, send_file

import behavior_config as cfg
from behavior.admin import is_admin
from behavior.report import write_reports
from behavior_analyzer import BehaviorAnalyzer, apply_mode
from monitor_core import find_matching_pids, shutdown_dns_pool

LOG_FILE = Path("app_connections.log")
EXPORT_DIR = Path("web_exports")
POLL_INTERVAL = getattr(cfg, "POLL_INTERVAL_SEC", 0.5)
MAX_CONN_EVENTS = 400
MAX_BEHAVIOR_EVENTS = 600

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False


@app.after_request
def _force_utf8(resp):
    """Ensure browsers decode HTML/JS/JSON as UTF-8 (avoids mojibake)."""
    ctype = resp.headers.get("Content-Type", "")
    if ctype.startswith("text/html") and "charset" not in ctype:
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
    elif ctype.startswith("application/json") and "charset" not in ctype:
        resp.headers["Content-Type"] = "application/json; charset=utf-8"
    elif ctype.startswith("text/event-stream") and "charset" not in ctype:
        resp.headers["Content-Type"] = "text/event-stream; charset=utf-8"
    return resp

_lock = threading.Lock()
_state = {
    "running": False,
    "target": "",
    "mode": "full",
    "outbound_only": False,
    "runtime": {},
    "processes": [],
    "connections": deque(maxlen=MAX_CONN_EVENTS),
    "behavior_events": deque(maxlen=MAX_BEHAVIOR_EVENTS),
    "sessions": [],
    "remotes": set(),
    "total_connections": 0,
    "packet_count": 0,
    "interesting_count": 0,
    "message": "Idle - choose a mode, enter an app name, press Start.",
    "last_saved": None,
    "last_report": None,
    "admin": is_admin(),
    "tool": cfg.TOOL_SIGNATURE,
    "version": getattr(cfg, "TOOL_VERSION", "2.0"),
}
_stop_event = threading.Event()
_worker: threading.Thread | None = None
_analyzer: BehaviorAnalyzer | None = None
_seen_event_ids: set[int] = set()


def _append_log(line: str) -> None:
    try:
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def _event_fingerprint(ev) -> int:
    return hash((ev.timestamp, ev.category, ev.action, ev.summary, ev.pid))


def _sync_from_analyzer(analyzer: BehaviorAnalyzer) -> None:
    """Pull live state from the BehaviorAnalyzer into the web snapshot."""
    matches = find_matching_pids(analyzer.target)
    processes = [
        {"pid": pid, "name": name, "connections": 0, "status": "running"}
        for pid, name in sorted(matches.items())
    ]

    # Count sockets per pid (best-effort)
    try:
        import psutil
        for p in processes:
            try:
                p["connections"] = len(psutil.Process(p["pid"]).net_connections(kind="inet"))
            except Exception:
                p["connections"] = 0
    except Exception:
        pass

    bus_events = analyzer.bus.snapshot()
    new_behavior = []
    for ev in bus_events:
        fp = _event_fingerprint(ev)
        if fp in _seen_event_ids:
            continue
        _seen_event_ids.add(fp)
        new_behavior.append(ev)

    # Cap fingerprint set
    if len(_seen_event_ids) > 20000:
        _seen_event_ids.clear()

    sessions = []
    try:
        if analyzer.rt.get("correlate"):
            sessions = [
                {
                    "session_id": s["session_id"],
                    "severity": s["severity"],
                    "summary": s.get("summary"),
                    "process": s.get("process"),
                    "pid": s.get("pid"),
                    "event_count": s.get("event_count"),
                    "flags": s.get("flags") or [],
                    "domains": (s.get("domains") or [])[:8],
                    "remote_ips": (s.get("remote_ips") or [])[:8],
                }
                for s in analyzer.correlation.scored_sessions()[:40]
            ]
    except Exception:
        sessions = []

    with _lock:
        _state["processes"] = processes
        _state["sessions"] = sessions
        _state["packet_count"] = getattr(analyzer.packets, "packet_count", 0)
        _state["interesting_count"] = sum(1 for e in bus_events if e.interesting)
        _state["runtime"] = dict(analyzer.rt)
        _state["admin"] = is_admin()

        if not processes:
            _state["message"] = f"Waiting for process matching '{analyzer.target}'..."
        else:
            _state["message"] = (
                f"Deep monitoring {len(processes)} process(es) | mode={_state['mode']} | "
                f"events={len(bus_events)} | packets={_state['packet_count']}"
            )

        for ev in new_behavior:
            item = {
                "timestamp": ev.timestamp,
                "category": ev.category,
                "action": ev.action,
                "summary": ev.summary,
                "pid": ev.pid,
                "process": ev.process,
                "interesting": ev.interesting,
                "session_id": ev.session_id,
                "details": {
                    k: ev.details.get(k)
                    for k in (
                        "flags", "remote_ip", "remote_port", "hostname", "protocol",
                        "direction", "local", "remote", "highlights", "tls_sni",
                    )
                    if isinstance(ev.details, dict) and k in ev.details
                },
            }
            _state["behavior_events"].appendleft(item)

            if ev.category == "network" and ev.action == "connection_new":
                d = ev.details or {}
                conn = {
                    "timestamp": ev.timestamp,
                    "process": ev.process,
                    "pid": ev.pid,
                    "protocol": d.get("protocol"),
                    "status": d.get("status"),
                    "direction": d.get("direction"),
                    "local": d.get("local"),
                    "remote": d.get("remote"),
                    "flags": d.get("flags") or [],
                }
                _state["connections"].appendleft(conn)
                _state["total_connections"] += 1
                if d.get("remote_ip") and d.get("remote_port"):
                    _state["remotes"].add(f"{d['remote_ip']}:{d['remote_port']}")
                _append_log(
                    f"[{ev.timestamp}]  {ev.process} (PID {ev.pid})  |  "
                    f"{d.get('protocol')}  |  {d.get('status')}  |  "
                    f"{d.get('direction')}  |  {d.get('local')}  ->  {d.get('remote')}"
                )


def _monitor_loop() -> None:
    global _analyzer
    while not _stop_event.is_set():
        with _lock:
            analyzer = _analyzer
            running = _state["running"]
        if not running or analyzer is None:
            time.sleep(POLL_INTERVAL)
            continue
        try:
            analyzer.poll_once()
            _sync_from_analyzer(analyzer)
        except Exception as exc:
            with _lock:
                _state["message"] = f"Monitor error: {exc}"
        time.sleep(POLL_INTERVAL)


def _start_worker() -> None:
    global _worker
    if _worker and _worker.is_alive():
        return
    _stop_event.clear()
    _worker = threading.Thread(target=_monitor_loop, daemon=True)
    _worker.start()


def _snapshot() -> dict:
    with _lock:
        return {
            "running": _state["running"],
            "target": _state["target"],
            "mode": _state["mode"],
            "outbound_only": _state["outbound_only"],
            "runtime": dict(_state["runtime"]),
            "processes": list(_state["processes"]),
            "events": list(_state["connections"]),  # backward compatible key
            "connections": list(_state["connections"]),
            "behavior_events": list(_state["behavior_events"]),
            "sessions": list(_state["sessions"]),
            "remotes": sorted(_state["remotes"]),
            "total_connections": _state["total_connections"],
            "unique_remotes": len(_state["remotes"]),
            "packet_count": _state["packet_count"],
            "interesting_count": _state["interesting_count"],
            "message": _state["message"],
            "last_saved": _state["last_saved"],
            "last_report": _state["last_report"],
            "admin": _state["admin"],
            "tool": _state["tool"],
            "version": _state["version"],
        }


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _safe_target(name: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "-_." else "_" for c in (name or "session"))
    return cleaned[:60] or "session"


def _build_markdown(data: dict) -> str:
    lines = [
        "# Osidev Deep Monitor Export",
        "",
        f"**{cfg.TOOL_SIGNATURE}** | v{data.get('version')}",
        "",
        f"- **Target:** `{data.get('target') or 'n/a'}`",
        f"- **Mode:** {data.get('mode')}",
        f"- **Outbound only:** {data.get('outbound_only')}",
        f"- **Connections:** {data.get('total_connections', 0)}",
        f"- **Packets:** {data.get('packet_count', 0)}",
        f"- **Interesting events:** {data.get('interesting_count', 0)}",
        f"- **Sessions:** {len(data.get('sessions') or [])}",
        f"- **Exported:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Runtime features",
        "",
        "```",
        json.dumps(data.get("runtime") or {}, indent=2),
        "```",
        "",
        "## Correlated sessions",
        "",
    ]
    for s in data.get("sessions") or []:
        lines.append(
            f"- `{s.get('session_id')}` **{s.get('severity')}** - {s.get('summary')} "
            f"({s.get('event_count')} events)"
        )
    lines += ["", "## Behavior events", ""]
    for e in (data.get("behavior_events") or [])[:200]:
        mark = " [!]" if e.get("interesting") else ""
        lines.append(
            f"- `{e.get('timestamp')}` [{e.get('category')}/{e.get('action')}] "
            f"{e.get('summary')}{mark}"
        )
    lines += ["", "## Connections", ""]
    for e in data.get("connections") or data.get("events") or []:
        lines.append(
            f"- `{e.get('timestamp')}` {e.get('process')} ({e.get('pid')}) "
            f"{e.get('local')} -> {e.get('remote')}"
        )
    lines += ["", "---", cfg.TOOL_SIGNATURE, ""]
    return "\n".join(lines)


def _build_csv(data: dict) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["timestamp", "category", "action", "process", "pid", "interesting", "summary"]
    )
    for e in data.get("behavior_events") or []:
        writer.writerow([
            e.get("timestamp", ""),
            e.get("category", ""),
            e.get("action", ""),
            e.get("process", ""),
            e.get("pid", ""),
            e.get("interesting", ""),
            e.get("summary", ""),
        ])
    return buf.getvalue()


def _build_txt(data: dict) -> str:
    lines = [
        "Osidev Deep Monitor Export",
        cfg.TOOL_SIGNATURE,
        f"Target: {data.get('target')}",
        f"Mode: {data.get('mode')}",
        "=" * 72,
        "",
    ]
    for e in data.get("behavior_events") or []:
        lines.append(
            f"[{e.get('timestamp')}] [{e.get('category')}/{e.get('action')}] {e.get('summary')}"
        )
    lines.append("")
    return "\n".join(lines)


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/status")
def api_status():
    return jsonify(_snapshot())


@app.route("/api/start", methods=["POST"])
def api_start():
    global _analyzer, _seen_event_ids
    data = request.get_json(silent=True) or {}
    target = (data.get("app") or "").strip()
    outbound_only = bool(data.get("outbound_only"))
    mode = (data.get("mode") or "full").strip().lower()
    if mode not in {"full", "deep", "connections", "packets", "light"}:
        mode = "full"
    if not target:
        return jsonify({"ok": False, "error": "Application name is required."}), 400

    # Stop previous analyzer if any
    with _lock:
        old = _analyzer
    if old is not None:
        try:
            old.stop()
        except Exception:
            pass

    runtime = apply_mode(mode)
    # Optional UI overrides
    if data.get("force_packets") is True:
        runtime["packets"] = True
        cfg.ENABLE_PACKET_CAPTURE = True
    if data.get("force_etw") is True:
        runtime["etw"] = True
        cfg.ENABLE_ETW_TRACE = True
    if data.get("force_frida") is True:
        runtime["frida"] = True
        cfg.ENABLE_FRIDA_HOOKS = True
    if data.get("force_memory") is True:
        runtime["memory"] = True
        cfg.ENABLE_MEMORY_STRINGS = True

    cfg.ENABLE_PACKET_CAPTURE = bool(runtime.get("packets"))

    analyzer = BehaviorAnalyzer(target, outbound_only=outbound_only, runtime=runtime)
    # Quiet packet console spam into Flask logs a bit — still useful
    analyzer.start_side_channels()

    _seen_event_ids = set()
    with _lock:
        _analyzer = analyzer
        _state["target"] = target
        _state["mode"] = mode
        _state["outbound_only"] = outbound_only
        _state["runtime"] = runtime
        _state["running"] = True
        _state["processes"] = []
        _state["connections"].clear()
        _state["behavior_events"].clear()
        _state["sessions"] = []
        _state["remotes"] = set()
        _state["total_connections"] = 0
        _state["packet_count"] = 0
        _state["interesting_count"] = 0
        _state["last_report"] = None
        _state["admin"] = is_admin()
        _state["message"] = f"Starting {mode} monitor for '{target}'..."

    _append_log(
        f"\n{'=' * 80}\n  Web deep monitor started\n"
        f"  Target: {target} | mode={mode} | outbound_only={outbound_only}\n"
        f"  {cfg.TOOL_SIGNATURE}\n{'=' * 80}"
    )
    _start_worker()
    return jsonify({"ok": True, **_snapshot()})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    global _analyzer
    with _lock:
        _state["running"] = False
        analyzer = _analyzer
        _state["message"] = "Stopped."
        _state["processes"] = []
    if analyzer is not None:
        try:
            analyzer.stop()
        except Exception:
            pass
    with _lock:
        _analyzer = None
    return jsonify({"ok": True, **_snapshot()})


@app.route("/api/report", methods=["POST"])
def api_report():
    """Generate professional Markdown + HTML behavior report from live bus."""
    with _lock:
        analyzer = _analyzer
        target = _state["target"] or "session"
        running = _state["running"]
    if analyzer is None:
        return jsonify({"ok": False, "error": "No active/previous analyzer session in memory. Start monitoring first."}), 400

    try:
        if analyzer.rt.get("correlate"):
            analyzer.correlation.rebuild(analyzer.bus.snapshot())
        md_path, html_path = write_reports(analyzer.bus, target)
        info = {
            "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "markdown": str(md_path.resolve()),
            "html": str(html_path.resolve()),
            "packets_log": str(cfg.PACKET_LOG_FILE.resolve()) if cfg.PACKET_LOG_FILE.exists() else None,
            "pcap": str(cfg.PACKET_PCAP_FILE.resolve()) if cfg.PACKET_PCAP_FILE.exists() else None,
            "running": running,
        }
        with _lock:
            _state["last_report"] = info
            _state["message"] = f"Report saved: {html_path.name}"
        return jsonify({"ok": True, **info, **_snapshot()})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/report/html")
def api_report_html():
    path = cfg.REPORT_HTML
    if not path.exists():
        return jsonify({"ok": False, "error": "No report yet - click Generate report first."}), 404
    return send_file(path.resolve(), as_attachment=False, download_name=path.name)


@app.route("/api/report/download/<kind>")
def api_report_download(kind: str):
    mapping = {
        "html": cfg.REPORT_HTML,
        "md": cfg.REPORT_MARKDOWN,
        "pcap": cfg.PACKET_PCAP_FILE,
        "packets": cfg.PACKET_LOG_FILE,
    }
    path = mapping.get(kind)
    if path is None or not path.exists():
        return jsonify({"ok": False, "error": f"No {kind} file available yet."}), 404
    return send_file(path.resolve(), as_attachment=True, download_name=path.name)


@app.route("/api/stream")
def api_stream():
    def generate():
        last_payload = ""
        while True:
            payload = json.dumps(_snapshot())
            if payload != last_payload:
                yield f"data: {payload}\n\n"
                last_payload = payload
            else:
                yield ": ping\n\n"
            time.sleep(0.75)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/export/<fmt>")
def api_export(fmt: str):
    fmt = fmt.lower().strip()
    data = _snapshot()
    stamp = _stamp()
    target = _safe_target(data.get("target") or "session")
    if fmt == "json":
        body, mime, filename = json.dumps(data, indent=2, ensure_ascii=False), "application/json", f"osidev_{target}_{stamp}.json"
    elif fmt in {"md", "markdown"}:
        body, mime, filename = _build_markdown(data), "text/markdown", f"osidev_{target}_{stamp}.md"
    elif fmt == "csv":
        body, mime, filename = _build_csv(data), "text/csv", f"osidev_{target}_{stamp}.csv"
    elif fmt == "txt":
        body, mime, filename = _build_txt(data), "text/plain", f"osidev_{target}_{stamp}.txt"
    else:
        return jsonify({"ok": False, "error": "Unsupported format."}), 400
    return Response(body, mimetype=mime, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.route("/api/save", methods=["POST"])
def api_save():
    data = request.get_json(silent=True) or {}
    formats = data.get("formats") or ["json", "md", "csv", "txt"]
    if isinstance(formats, str):
        formats = [formats]
    snap = _snapshot()
    if not snap.get("behavior_events") and not snap.get("connections") and not snap.get("total_connections"):
        return jsonify({"ok": False, "error": "Nothing to save yet - start monitoring first."}), 400

    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    target = _safe_target(snap.get("target") or "session")
    builders = {
        "json": ("json", lambda: json.dumps(snap, indent=2, ensure_ascii=False)),
        "md": ("md", lambda: _build_markdown(snap)),
        "markdown": ("md", lambda: _build_markdown(snap)),
        "csv": ("csv", lambda: _build_csv(snap)),
        "txt": ("txt", lambda: _build_txt(snap)),
    }
    saved = []
    for fmt in formats:
        key = str(fmt).lower().strip()
        if key not in builders:
            continue
        ext, builder = builders[key]
        path = EXPORT_DIR / f"osidev_{target}_{stamp}.{ext}"
        path.write_text(builder(), encoding="utf-8")
        saved.append({"format": ext, "path": str(path.resolve())})

    info = {
        "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "files": saved,
        "export_dir": str(EXPORT_DIR.resolve()),
        "tool": cfg.TOOL_SIGNATURE,
    }
    with _lock:
        _state["last_saved"] = info
        _state["message"] = f"Saved {len(saved)} file(s) to {EXPORT_DIR.resolve()}"
    return jsonify({"ok": True, **info, **_snapshot()})


@app.route("/api/download/log")
def api_download_log():
    if not LOG_FILE.exists():
        return jsonify({"ok": False, "error": "No app_connections.log yet."}), 404
    return send_file(LOG_FILE.resolve(), as_attachment=True, download_name=f"app_connections_{_stamp()}.log")


@app.route("/api/exports")
def api_list_exports():
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    files = []
    for p in sorted(EXPORT_DIR.glob("osidev_*"), key=lambda x: x.stat().st_mtime, reverse=True):
        if p.is_file():
            files.append({
                "name": p.name,
                "path": str(p.resolve()),
                "size": p.stat().st_size,
                "modified": datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            })
    return jsonify({"ok": True, "export_dir": str(EXPORT_DIR.resolve()), "files": files[:100]})


@app.route("/api/exports/<path:filename>")
def api_get_export(filename: str):
    safe = Path(filename).name
    path = EXPORT_DIR / safe
    if not path.exists() or not path.is_file():
        return jsonify({"ok": False, "error": "File not found."}), 404
    return send_file(path.resolve(), as_attachment=True, download_name=safe)


def main() -> None:
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    cfg.LOG_DIR.mkdir(parents=True, exist_ok=True)
    print("Osidev Monitoring — Deep Web Dashboard")
    print(cfg.TOOL_SIGNATURE)
    print(f"Admin: {is_admin()}")
    print("Open: http://127.0.0.1:5050")
    print(f"Exports: {EXPORT_DIR.resolve()}")
    print("Press Ctrl+C to stop.")
    if not is_admin():
        print("WARNING: Not elevated — ETW/packets/memory/Frida may be limited.")
    try:
        app.run(host="127.0.0.1", port=5050, debug=False, threaded=True)
    finally:
        _stop_event.set()
        with _lock:
            analyzer = _analyzer
        if analyzer is not None:
            try:
                analyzer.stop()
            except Exception:
                pass
        shutdown_dns_pool()


if __name__ == "__main__":
    main()
