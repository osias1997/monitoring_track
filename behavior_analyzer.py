#!/usr/bin/env python3
"""
Behavior Analyzer — reverse-engineering / behavioral analysis for Windows apps.

Tracks what happens before, during, and after network connections:
  process modules, children, resources, files, registry, DNS, optional memory.

Install:
  pip install psutil watchdog colorama rich
  # optional: pip install scapy frida frida-tools

Run (Administrator recommended):
  python behavior_analyzer.py chrome
  python behavior_analyzer.py --outbound-only discord
  python behavior_analyzer.py  # prompts for target

Config toggles live in behavior_config.py
"""

from __future__ import annotations

import argparse
import sys
import time
import uuid

import behavior_config as cfg
from behavior.admin import ensure_admin_warning, is_admin
from behavior.events import BehaviorEvent, EventBus, now_epoch
from behavior.file_activity import DirectoryWatcher, OpenFilesPoller
from behavior.highlights import annotate_connection
from behavior.memory_strings import maybe_memory_snapshot
from behavior.network_deep import DnsTracker, OptionalPacketSniffer, connection_details
from behavior.optional_hooks import try_etw_note, try_start_frida
from behavior.process_inspect import ProcessTracker
from behavior.registry_watch import RegistryWatcher
from behavior.report import write_reports
from monitor_core import connection_key, find_matching_pids, shutdown_dns_pool


def _console():
    if cfg.ENABLE_RICH_CONSOLE:
        try:
            from rich.console import Console
            from rich.table import Table
            return Console(), Table
        except ImportError:
            pass
    return None, None


def _print(msg: str, style: str | None = None) -> None:
    console, _ = _console()
    if console is not None:
        console.print(msg, style=style)
    else:
        try:
            from colorama import Fore, Style, init
            if cfg.ENABLE_COLORAMA:
                init(autoreset=True)
                colors = {
                    "green": Fore.GREEN,
                    "yellow": Fore.YELLOW,
                    "cyan": Fore.CYAN,
                    "red": Fore.RED,
                    "magenta": Fore.MAGENTA,
                }
                prefix = colors.get(style or "", "")
                print(prefix + msg + (Style.RESET_ALL if prefix else ""))
                return
        except ImportError:
            pass
        print(msg)


class BehaviorAnalyzer:
    def __init__(self, target: str, outbound_only: bool) -> None:
        self.target = target
        self.outbound_only = outbound_only
        self.bus = EventBus()
        self.seen_conns: set[tuple] = set()
        self.process_tracker = ProcessTracker(self.bus)
        self.open_files = OpenFilesPoller(self.bus)
        self.dir_watcher = DirectoryWatcher(self.bus)
        self.registry = RegistryWatcher(self.bus)
        self.dns = DnsTracker(self.bus)
        self.sniffer = OptionalPacketSniffer(self.bus)
        self._frida_attached: set[int] = set()
        self._baseline_ready = False

    def start_side_channels(self) -> None:
        if cfg.ENABLE_FILE_ACTIVITY:
            ok = self.dir_watcher.start()
            _print(
                f"[+] Directory watcher: {'on' if ok else 'off'}",
                "cyan" if ok else "yellow",
            )
        if cfg.ENABLE_SCAPY_SNIFF:
            self.sniffer.start()
        try_etw_note(self.bus)

    def stop(self) -> None:
        self.dir_watcher.stop()
        self.sniffer.stop()

    def _session_id(self, rec: dict) -> str:
        remote = rec.get("remote") or "local"
        return f"{rec.get('pid')}-{remote}-{uuid.uuid4().hex[:8]}"

    def on_new_connection(self, rec: dict, proc_snap: dict | None) -> None:
        """Deep dive when a new connection appears."""
        epoch = now_epoch()
        sid = self._session_id(rec)
        flags = annotate_connection(rec) if cfg.ENABLE_HIGHLIGHTS else []
        interesting = bool(flags)

        # Sequence: events shortly before this connection
        before = self.bus.recent_before(epoch, seconds=3.0) if cfg.ENABLE_SEQUENCE_ANALYSIS else []

        details = dict(rec)
        details["flags"] = flags
        details["modules_sample"] = (proc_snap or {}).get("modules", [])[:25]
        details["cmdline"] = (proc_snap or {}).get("cmdline")
        details["environ_interesting"] = (proc_snap or {}).get("environ_interesting")
        details["children"] = (proc_snap or {}).get("children")
        details["open_files_sample"] = (proc_snap or {}).get("open_files", [])[:30]
        details["cpu_percent"] = (proc_snap or {}).get("cpu_percent")
        details["memory_rss"] = (proc_snap or {}).get("memory_rss")
        details["num_threads"] = (proc_snap or {}).get("num_threads")
        details["fs_near_event"] = self.dir_watcher.recent_around(epoch)
        details["pre_events"] = [
            {"action": e.action, "summary": e.summary, "timestamp": e.timestamp}
            for e in before
        ]

        self.bus.emit(BehaviorEvent(
            category="network",
            action="connection_new",
            summary=(
                f"{rec['protocol']} {rec['status']} {rec['direction']} "
                f"{rec['local']} -> {rec['remote']}"
            ),
            pid=rec.get("pid"),
            process=rec.get("process"),
            details=details,
            interesting=interesting,
            session_id=sid,
        ))

        # Attach pre-events to this session for the report sequence
        for e in before:
            self.bus.emit(BehaviorEvent(
                category=e.category,
                action=f"pre_{e.action}",
                summary=f"[before] {e.summary}",
                pid=e.pid,
                process=e.process,
                details=e.details,
                interesting=e.interesting,
                session_id=sid,
            ))

        style = "red" if interesting else "green"
        _print(
            f"[{rec.get('timestamp', '')}] CONN  "
            f"{rec.get('process')}({rec.get('pid')})  "
            f"{rec.get('local')} -> {rec.get('remote')}  "
            f"{rec.get('protocol')}/{rec.get('status')}  "
            f"{('FLAGS:' + ','.join(flags)) if flags else ''}",
            style,
        )

        maybe_memory_snapshot(
            self.bus, int(rec["pid"]), str(rec.get("process") or ""), sid
        )

    def poll_once(self) -> None:
        matches = find_matching_pids(self.target)
        if not matches:
            _print(f"[…] Waiting for process matching '{self.target}'…", "yellow")
            return

        # Process / file / registry / dns side polls
        snaps: dict[int, dict] = {}
        for pid, name in matches.items():
            if cfg.ENABLE_PROCESS_INSPECTION:
                snaps[pid] = self.process_tracker.poll(pid, name)
                # Warm cpu_percent
                try:
                    import psutil
                    psutil.Process(pid).cpu_percent(interval=0.0)
                except Exception:
                    pass
            if cfg.ENABLE_FILE_ACTIVITY:
                self.open_files.poll(pid, name)
            if cfg.ENABLE_FRIDA_HOOKS and pid not in self._frida_attached:
                if try_start_frida(self.bus, pid):
                    self._frida_attached.add(pid)

        if cfg.ENABLE_REGISTRY_WATCH:
            self.registry.poll()
        if cfg.ENABLE_DNS_TRACKING:
            self.dns.poll()

        # Connections via shared scanner (also records new ones)
        # Use local seen set + connection_details for richer records
        import psutil
        from monitor_core import infer_direction

        for pid, name in matches.items():
            try:
                proc = psutil.Process(pid)
                conns = proc.net_connections(kind="inet")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            for conn in conns:
                direction = infer_direction(conn)
                if self.outbound_only and direction != "outbound":
                    continue
                key = connection_key(pid, conn)
                if key in self.seen_conns:
                    continue
                self.seen_conns.add(key)

                # Skip flood of pre-existing sockets on first observation
                if not self._baseline_ready:
                    continue

                rec = connection_details(name, pid, conn)
                from datetime import datetime
                rec["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                self.on_new_connection(rec, snaps.get(pid))

        if not self._baseline_ready:
            self._baseline_ready = True
            self.bus.emit(BehaviorEvent(
                category="system",
                action="baseline_ready",
                summary=f"Baseline captured ({len(self.seen_conns)} existing connections ignored)",
                details={"existing_connections": len(self.seen_conns)},
            ))
            _print(
                f"[+] Baseline ready — monitoring NEW activity "
                f"(ignored {len(self.seen_conns)} existing connections)",
                "cyan",
            )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Behavioral analysis / reverse-engineering monitor for Windows apps."
    )
    p.add_argument("app", nargs="?", default=cfg.DEFAULT_TARGET or None,
                   help="Process name or executable path")
    p.add_argument("-o", "--outbound-only", action="store_true",
                   default=cfg.OUTBOUND_ONLY,
                   help="Only analyze outbound connections")
    p.add_argument("--report", action="store_true",
                   help="Write reports now from existing events.jsonl context (after run)")
    p.add_argument("--no-elevate-prompt", action="store_true",
                   help="Do not ask to relaunch as Administrator")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    if cfg.WARN_IF_NOT_ADMIN:
        ensure_admin_warning(offer_elevation=cfg.OFFER_ELEVATION and not args.no_elevate_prompt)

    target = (args.app or "").strip() or input("Application name or executable path: ").strip()
    if not target:
        print("No target specified.", file=sys.stderr)
        sys.exit(1)

    cfg.LOG_DIR.mkdir(parents=True, exist_ok=True)

    _print("=" * 78, "cyan")
    _print("  BEHAVIOR ANALYZER", "cyan")
    _print(f"  {cfg.TOOL_SIGNATURE}", "cyan")
    _print(f"  Target     : {target}")
    _print(f"  Admin      : {is_admin()}")
    _print(f"  Logs       : {cfg.LOG_DIR.resolve()}")
    _print(f"  Features   : proc={cfg.ENABLE_PROCESS_INSPECTION} "
           f"files={cfg.ENABLE_FILE_ACTIVITY} reg={cfg.ENABLE_REGISTRY_WATCH} "
           f"dns={cfg.ENABLE_DNS_TRACKING} mem={cfg.ENABLE_MEMORY_STRINGS} "
           f"scapy={cfg.ENABLE_SCAPY_SNIFF} frida={cfg.ENABLE_FRIDA_HOOKS}")
    _print("  Stop       : Ctrl+C  (auto-report on exit)", "cyan")
    _print("=" * 78, "cyan")

    analyzer = BehaviorAnalyzer(target, outbound_only=args.outbound_only)
    analyzer.start_side_channels()
    analyzer.bus.emit(BehaviorEvent(
        category="system",
        action="monitor_start",
        summary=f"Started behavior monitor for '{target}'",
        details={"admin": is_admin()},
    ))

    try:
        while True:
            analyzer.poll_once()
            time.sleep(cfg.POLL_INTERVAL_SEC)
    except KeyboardInterrupt:
        _print("\n[!] Stopping… generating reports", "magenta")
    finally:
        analyzer.stop()
        if cfg.AUTO_REPORT_ON_EXIT:
            md, html_path = write_reports(analyzer.bus, target)
            _print(f"[+] Markdown report: {md}", "green")
            _print(f"[+] HTML report    : {html_path}", "green")
        shutdown_dns_pool()


if __name__ == "__main__":
    main()
