#!/usr/bin/env python3
"""
Live web dashboard for app connection monitoring.
Requires: pip install psutil flask

Run:
    python web_dashboard.py

Then open http://127.0.0.1:5050 in your browser.

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

from monitor_core import scan_processes, shutdown_dns_pool

LOG_FILE = Path("app_connections.log")
EXPORT_DIR = Path("web_exports")
POLL_INTERVAL = 1.0
MAX_EVENTS = 500

app = Flask(__name__)

_lock = threading.Lock()
_state = {
    "running": False,
    "target": "",
    "outbound_only": False,
    "processes": [],
    "events": deque(maxlen=MAX_EVENTS),
    "remotes": set(),
    "seen": set(),
    "total_connections": 0,
    "message": "Idle — enter an app name and press Start.",
    "last_saved": None,
}
_stop_event = threading.Event()
_worker: threading.Thread | None = None


def _append_log(line: str) -> None:
    with LOG_FILE.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _monitor_loop() -> None:
    while not _stop_event.is_set():
        with _lock:
            target = _state["target"]
            outbound_only = _state["outbound_only"]
            seen = _state["seen"]

        if not target:
            time.sleep(POLL_INTERVAL)
            continue

        try:
            processes, new_conns, new_remotes = scan_processes(target, outbound_only, seen)
        except Exception as exc:
            with _lock:
                _state["message"] = f"Scan error: {exc}"
            time.sleep(POLL_INTERVAL)
            continue

        with _lock:
            _state["processes"] = processes
            if not processes:
                _state["message"] = f"Waiting for process matching '{target}'…"
            else:
                _state["message"] = (
                    f"Monitoring {len(processes)} process(es) for '{target}'"
                )
            _state["remotes"] |= new_remotes
            for rec in new_conns:
                _state["events"].appendleft(rec)
                _state["total_connections"] += 1
                _append_log(
                    f"[{rec['timestamp']}]  {rec['process']} (PID {rec['pid']})  |  "
                    f"{rec['protocol']}  |  {rec['status']:<12}  |  "
                    f"{rec['direction']:<8}  |  {rec['local']}  ->  {rec['remote']}"
                )

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
            "outbound_only": _state["outbound_only"],
            "processes": list(_state["processes"]),
            "events": list(_state["events"]),
            "remotes": sorted(_state["remotes"]),
            "total_connections": _state["total_connections"],
            "unique_remotes": len(_state["remotes"]),
            "message": _state["message"],
            "last_saved": _state["last_saved"],
            "tool": "Tool made by Osidev",
        }


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _safe_target(name: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "-_." else "_" for c in (name or "session"))
    return cleaned[:60] or "session"


def _build_markdown(data: dict) -> str:
    lines = [
        "# Connection Monitor Export",
        "",
        "**Tool made by Osidev**",
        "",
        f"- **Target:** `{data.get('target') or 'n/a'}`",
        f"- **Outbound only:** {data.get('outbound_only')}",
        f"- **Connections seen:** {data.get('total_connections', 0)}",
        f"- **Unique remotes:** {data.get('unique_remotes', 0)}",
        f"- **Exported:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Matching processes",
        "",
    ]
    procs = data.get("processes") or []
    if procs:
        for p in procs:
            lines.append(
                f"- `{p.get('name')}` PID {p.get('pid')} — "
                f"{p.get('connections', 0)} connections ({p.get('status')})"
            )
    else:
        lines.append("- None")

    lines += ["", "## Unique remotes", ""]
    remotes = data.get("remotes") or []
    if remotes:
        for r in remotes:
            lines.append(f"- `{r}`")
    else:
        lines.append("- None")

    lines += ["", "## Connection feed", "", "| Time | Process | PID | Proto | Status | Dir | Local | Remote |", "|---|---|---|---|---|---|---|---|"]
    for e in data.get("events") or []:
        lines.append(
            f"| {e.get('timestamp','')} | {e.get('process','')} | {e.get('pid','')} | "
            f"{e.get('protocol','')} | {e.get('status','')} | {e.get('direction','')} | "
            f"{e.get('local','')} | {e.get('remote','')} |"
        )
    lines += ["", "---", "Tool made by Osidev", ""]
    return "\n".join(lines)


def _build_csv(data: dict) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["timestamp", "process", "pid", "protocol", "status", "direction", "local", "remote"]
    )
    for e in data.get("events") or []:
        writer.writerow([
            e.get("timestamp", ""),
            e.get("process", ""),
            e.get("pid", ""),
            e.get("protocol", ""),
            e.get("status", ""),
            e.get("direction", ""),
            e.get("local", ""),
            e.get("remote", ""),
        ])
    return buf.getvalue()


def _build_txt(data: dict) -> str:
    lines = [
        "Osidev Monitoring — Connection Export",
        "Tool made by Osidev",
        f"Target: {data.get('target') or 'n/a'}",
        f"Connections: {data.get('total_connections', 0)}",
        f"Remotes: {data.get('unique_remotes', 0)}",
        "=" * 72,
        "",
    ]
    for e in data.get("events") or []:
        lines.append(
            f"[{e.get('timestamp')}]  {e.get('process')} (PID {e.get('pid')})  |  "
            f"{e.get('protocol')}  |  {e.get('status')}  |  {e.get('direction')}  |  "
            f"{e.get('local')}  ->  {e.get('remote')}"
        )
    lines += ["", "Unique remotes:"]
    for r in data.get("remotes") or []:
        lines.append(f"  - {r}")
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
    data = request.get_json(silent=True) or {}
    target = (data.get("app") or "").strip()
    outbound_only = bool(data.get("outbound_only"))
    if not target:
        return jsonify({"ok": False, "error": "Application name is required."}), 400

    with _lock:
        _state["target"] = target
        _state["outbound_only"] = outbound_only
        _state["running"] = True
        _state["processes"] = []
        _state["events"].clear()
        _state["remotes"] = set()
        _state["seen"] = set()
        _state["total_connections"] = 0
        _state["message"] = f"Starting monitor for '{target}'…"

    _append_log(
        f"\n{'=' * 80}\n  Web monitor started for: {target} "
        f"({'outbound only' if outbound_only else 'all'})\n"
        f"  Tool made by Osidev\n{'=' * 80}"
    )
    _start_worker()
    return jsonify({"ok": True, **_snapshot()})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    with _lock:
        _state["running"] = False
        _state["target"] = ""
        _state["processes"] = []
        _state["message"] = "Stopped."
    return jsonify({"ok": True, **_snapshot()})


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
    """Download current session as json / md / csv / txt."""
    fmt = fmt.lower().strip()
    data = _snapshot()
    stamp = _stamp()
    target = _safe_target(data.get("target") or "session")

    if fmt == "json":
        body = json.dumps(data, indent=2, ensure_ascii=False)
        mime = "application/json"
        filename = f"osidev_{target}_{stamp}.json"
    elif fmt in {"md", "markdown"}:
        body = _build_markdown(data)
        mime = "text/markdown"
        filename = f"osidev_{target}_{stamp}.md"
    elif fmt == "csv":
        body = _build_csv(data)
        mime = "text/csv"
        filename = f"osidev_{target}_{stamp}.csv"
    elif fmt == "txt":
        body = _build_txt(data)
        mime = "text/plain"
        filename = f"osidev_{target}_{stamp}.txt"
    else:
        return jsonify({"ok": False, "error": "Unsupported format. Use json, md, csv, txt."}), 400

    return Response(
        body,
        mimetype=mime,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/api/save", methods=["POST"])
def api_save():
    """Save current session to web_exports/ on disk (json + md + csv + txt)."""
    data = request.get_json(silent=True) or {}
    formats = data.get("formats") or ["json", "md", "csv", "txt"]
    if isinstance(formats, str):
        formats = [formats]

    snap = _snapshot()
    if not snap.get("events") and not snap.get("remotes") and not snap.get("total_connections"):
        return jsonify({
            "ok": False,
            "error": "Nothing to save yet — start monitoring and wait for connections.",
        }), 400

    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()
    target = _safe_target(snap.get("target") or "session")
    saved: list[dict] = []

    builders = {
        "json": ("json", lambda: json.dumps(snap, indent=2, ensure_ascii=False)),
        "md": ("md", lambda: _build_markdown(snap)),
        "markdown": ("md", lambda: _build_markdown(snap)),
        "csv": ("csv", lambda: _build_csv(snap)),
        "txt": ("txt", lambda: _build_txt(snap)),
    }

    for fmt in formats:
        key = str(fmt).lower().strip()
        if key not in builders:
            continue
        ext, builder = builders[key]
        path = EXPORT_DIR / f"osidev_{target}_{stamp}.{ext}"
        path.write_text(builder(), encoding="utf-8")
        saved.append({"format": ext, "path": str(path.resolve())})

    # Also copy / refresh the live app_connections.log pointer info
    log_info = {
        "exists": LOG_FILE.exists(),
        "path": str(LOG_FILE.resolve()) if LOG_FILE.exists() else None,
        "size": LOG_FILE.stat().st_size if LOG_FILE.exists() else 0,
    }

    info = {
        "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "files": saved,
        "export_dir": str(EXPORT_DIR.resolve()),
        "connection_log": log_info,
        "tool": "Tool made by Osidev",
    }
    with _lock:
        _state["last_saved"] = info
        _state["message"] = f"Saved {len(saved)} file(s) to {EXPORT_DIR.resolve()}"

    return jsonify({"ok": True, **info, **_snapshot()})


@app.route("/api/download/log")
def api_download_log():
    """Download the running app_connections.log file."""
    if not LOG_FILE.exists():
        return jsonify({"ok": False, "error": "No app_connections.log yet."}), 404
    return send_file(
        LOG_FILE.resolve(),
        as_attachment=True,
        download_name=f"app_connections_{_stamp()}.log",
        mimetype="text/plain",
    )


@app.route("/api/exports")
def api_list_exports():
    """List previously saved exports in web_exports/."""
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
    """Download a previously saved export by filename."""
    safe = Path(filename).name
    path = EXPORT_DIR / safe
    if not path.exists() or not path.is_file():
        return jsonify({"ok": False, "error": "File not found."}), 404
    return send_file(path.resolve(), as_attachment=True, download_name=safe)


def main() -> None:
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    print("Osidev Monitoring — Live dashboard")
    print("Tool made by Osidev")
    print("Open: http://127.0.0.1:5050")
    print(f"Exports folder: {EXPORT_DIR.resolve()}")
    print("Press Ctrl+C to stop.")
    try:
        app.run(host="127.0.0.1", port=5050, debug=False, threaded=True)
    finally:
        _stop_event.set()
        shutdown_dns_pool()


if __name__ == "__main__":
    main()
