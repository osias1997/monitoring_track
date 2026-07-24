#!/usr/bin/env python3
"""
Live web dashboard for app connection monitoring.
Requires: pip install psutil flask

Run:
    python web_dashboard.py

Then open http://127.0.0.1:5050 in your browser.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request

from monitor_core import scan_processes, shutdown_dns_pool

LOG_FILE = Path("app_connections.log")
POLL_INTERVAL = 1.0
MAX_EVENTS = 500

app = Flask(__name__)

# Shared monitor state (protected by lock)
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
}
_stop_event = threading.Event()
_worker: threading.Thread | None = None


def _append_log(line: str) -> None:
    with LOG_FILE.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _monitor_loop() -> None:
    """Background poller that feeds the live dashboard state."""
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
        except Exception as exc:  # keep UI alive on unexpected errors
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
        }


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
        f"({'outbound only' if outbound_only else 'all'})\n{'=' * 80}"
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
    """Server-Sent Events stream for near real-time UI updates."""

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


def main() -> None:
    print("Live dashboard: http://127.0.0.1:5050")
    print("Press Ctrl+C to stop.")
    try:
        app.run(host="127.0.0.1", port=5050, debug=False, threaded=True)
    finally:
        _stop_event.set()
        shutdown_dns_pool()


if __name__ == "__main__":
    main()
