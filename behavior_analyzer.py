#!/usr/bin/env python3
"""
Behavior Analyzer — reverse-engineering / behavioral analysis for Windows apps.

Includes deep packet capture (Scapy) scoped to the target process endpoints.

Install:
  pip install psutil watchdog colorama rich scapy
  # Npcap (required for sniffing): https://npcap.com/
  # optional: pip install frida frida-tools

Run as Administrator for best results:
  python behavior_analyzer.py
  python behavior_analyzer.py chrome --mode full
  python behavior_analyzer.py chrome --mode packets
  python behavior_analyzer.py chrome --packets
  python behavior_analyzer.py --mode light notepad

Modes:
  full         — process + files + registry + DNS + packets
  connections  — connection/process focus (no packet capture)
  packets      — packet capture + connection correlation
  light        — connections only (minimal side channels)

Config toggles: behavior_config.py
Tool made by Osidev
"""

from __future__ import annotations

import argparse
import sys
import time
import uuid
from datetime import datetime

import behavior_config as cfg
from behavior.admin import ensure_admin_warning, is_admin
from behavior.events import BehaviorEvent, EventBus, now_epoch
from behavior.file_activity import DirectoryWatcher, OpenFilesPoller
from behavior.highlights import annotate_connection
from behavior.memory_strings import maybe_memory_snapshot
from behavior.network_deep import DnsTracker, OptionalPacketSniffer, connection_details
from behavior.optional_hooks import try_etw_note, try_start_frida
from behavior.packet_capture import ProcessPacketCapture
from behavior.process_inspect import ProcessTracker
from behavior.registry_watch import RegistryWatcher
from behavior.report import write_reports
from monitor_core import connection_key, find_matching_pids, shutdown_dns_pool


MODES = {
    "full": {
        "process": True, "files": True, "registry": True, "dns": True,
        "packets": True, "memory": None,  # None = follow config
    },
    "connections": {
        "process": True, "files": False, "registry": False, "dns": True,
        "packets": False, "memory": False,
    },
    "packets": {
        "process": True, "files": False, "registry": False, "dns": True,
        "packets": True, "memory": False,
    },
    "light": {
        "process": False, "files": False, "registry": False, "dns": False,
        "packets": False, "memory": False,
    },
}


def _print(msg: str, style: str | None = None) -> None:
    if cfg.ENABLE_RICH_CONSOLE:
        try:
            from rich.console import Console
            Console().print(msg, style=style)
            return
        except ImportError:
            pass
    try:
        from colorama import Fore, Style, init
        if cfg.ENABLE_COLORAMA:
            init(autoreset=True)
            colors = {
                "green": Fore.GREEN, "yellow": Fore.YELLOW, "cyan": Fore.CYAN,
                "red": Fore.RED, "magenta": Fore.MAGENTA, "bold": Fore.WHITE,
            }
            prefix = colors.get(style or "", "")
            print(prefix + msg + (Style.RESET_ALL if prefix else ""))
            return
    except ImportError:
        pass
    print(msg)


def apply_mode(mode: str) -> dict:
    """Overlay mode presets onto runtime feature flags (does not rewrite config file)."""
    preset = MODES.get(mode, MODES["full"])
    runtime = {
        "process": preset["process"] and cfg.ENABLE_PROCESS_INSPECTION,
        "files": preset["files"] and cfg.ENABLE_FILE_ACTIVITY,
        "registry": preset["registry"] and cfg.ENABLE_REGISTRY_WATCH,
        "dns": preset["dns"] and cfg.ENABLE_DNS_TRACKING,
        "packets": preset["packets"] and cfg.ENABLE_PACKET_CAPTURE,
        "memory": cfg.ENABLE_MEMORY_STRINGS if preset["memory"] is None else preset["memory"],
        "frida": cfg.ENABLE_FRIDA_HOOKS,
        "legacy_scapy": cfg.ENABLE_SCAPY_SNIFF and not (preset["packets"] and cfg.ENABLE_PACKET_CAPTURE),
    }
    return runtime


def interactive_menu() -> tuple[str, str, bool]:
    """Simple main menu when launched without a target/mode."""
    print()
    print("=" * 60)
    print("  Osidev Monitoring — Behavior Analyzer")
    print("  Tool made by Osidev")
    print("=" * 60)
    print("  1) Full analysis (process + files + registry + packets)")
    print("  2) Connections only")
    print("  3) Packet-focused (capture + connection correlation)")
    print("  4) Light (connections, minimal extras)")
    print("  5) Quit")
    print("=" * 60)
    choice = input("Select mode [1]: ").strip() or "1"
    mode_map = {"1": "full", "2": "connections", "3": "packets", "4": "light"}
    if choice == "5":
        sys.exit(0)
    mode = mode_map.get(choice, "full")
    target = input("Application name or executable path: ").strip()
    outbound = input("Outbound connections only? [y/N]: ").strip().lower() in {"y", "yes"}
    return target, mode, outbound


class BehaviorAnalyzer:
    def __init__(self, target: str, outbound_only: bool, runtime: dict) -> None:
        self.target = target
        self.outbound_only = outbound_only
        self.rt = runtime
        self.bus = EventBus()
        self.seen_conns: set[tuple] = set()
        self.process_tracker = ProcessTracker(self.bus)
        self.open_files = OpenFilesPoller(self.bus)
        self.dir_watcher = DirectoryWatcher(self.bus)
        self.registry = RegistryWatcher(self.bus)
        self.dns = DnsTracker(self.bus)
        self.legacy_sniffer = OptionalPacketSniffer(self.bus)
        self.packets = ProcessPacketCapture(self.bus, on_packet=self._on_packet_console)
        self._frida_attached: set[int] = set()
        self._baseline_ready = False
        self._start_epoch = time.time()

    def _on_packet_console(self, record: dict) -> None:
        hl = record.get("highlights") or []
        if not hl and not cfg.PACKET_EMIT_ALL_EVENTS:
            return
        style = "red" if hl else "green"
        _print(f"[PKT] {record.get('summary')}", style)

    def start_side_channels(self) -> None:
        if self.rt["files"]:
            ok = self.dir_watcher.start()
            _print(f"[+] Directory watcher: {'on' if ok else 'off'}", "cyan" if ok else "yellow")
        if self.rt["packets"]:
            if not is_admin():
                _print(
                    "[!] Packet capture needs Administrator + Npcap (https://npcap.com/)",
                    "red",
                )
            ok = self.packets.start()
            _print(
                f"[+] Packet capture: {'on' if ok else 'FAILED'}",
                "cyan" if ok else "red",
            )
            if ok:
                _print(f"    log : {cfg.PACKET_LOG_FILE.resolve()}", "cyan")
                _print(f"    pcap: {cfg.PACKET_PCAP_FILE.resolve()}", "cyan")
        elif self.rt["legacy_scapy"]:
            self.legacy_sniffer.start()
        try_etw_note(self.bus)

    def stop(self) -> None:
        self.dir_watcher.stop()
        self.legacy_sniffer.stop()
        self.packets.stop()

    def _session_id(self, rec: dict) -> str:
        remote = rec.get("remote") or "local"
        return f"{rec.get('pid')}-{remote}-{uuid.uuid4().hex[:8]}"

    def on_new_connection(self, rec: dict, proc_snap: dict | None) -> None:
        epoch = now_epoch()
        sid = self._session_id(rec)
        flags = annotate_connection(rec) if cfg.ENABLE_HIGHLIGHTS else []
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
        details["fs_near_event"] = self.dir_watcher.recent_around(epoch) if self.rt["files"] else []
        details["pre_events"] = [
            {"action": e.action, "summary": e.summary, "timestamp": e.timestamp}
            for e in before
        ]
        # Correlate recent interesting packets with this connection
        remote_ip = rec.get("remote_ip")
        related_pkts = [
            p for p in self.packets.highlights[-30:]
            if remote_ip and (p.get("dst_ip") == remote_ip or p.get("src_ip") == remote_ip)
        ]
        details["related_packets"] = [
            {"timestamp": p.get("timestamp"), "summary": p.get("summary"), "highlights": p.get("highlights")}
            for p in related_pkts
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
            interesting=bool(flags) or bool(related_pkts),
            session_id=sid,
        ))

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

        style = "red" if flags or related_pkts else "green"
        _print(
            f"[{rec.get('timestamp', '')}] CONN  "
            f"{rec.get('process')}({rec.get('pid')})  "
            f"{rec.get('local')} -> {rec.get('remote')}  "
            f"{rec.get('protocol')}/{rec.get('status')}  "
            f"{('FLAGS:' + ','.join(flags)) if flags else ''}",
            style,
        )

        if self.rt["memory"]:
            maybe_memory_snapshot(
                self.bus, int(rec["pid"]), str(rec.get("process") or ""), sid
            )

    def poll_once(self) -> None:
        matches = find_matching_pids(self.target)
        if not matches:
            _print(f"[…] Waiting for process matching '{self.target}'…", "yellow")
            return

        pids = set(matches.keys())
        if self.rt["packets"]:
            self.packets.update_process_endpoints(pids)

        snaps: dict[int, dict] = {}
        for pid, name in matches.items():
            if self.rt["process"]:
                snaps[pid] = self.process_tracker.poll(pid, name)
                try:
                    import psutil
                    psutil.Process(pid).cpu_percent(interval=0.0)
                except Exception:
                    pass
            if self.rt["files"]:
                self.open_files.poll(pid, name)
            if self.rt["frida"] and pid not in self._frida_attached:
                if try_start_frida(self.bus, pid):
                    self._frida_attached.add(pid)

        if self.rt["registry"]:
            self.registry.poll()
        if self.rt["dns"]:
            self.dns.poll()

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
                if not self._baseline_ready:
                    continue
                rec = connection_details(name, pid, conn)
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
        description="Osidev behavioral analysis / packet monitor for Windows apps."
    )
    p.add_argument("app", nargs="?", default=cfg.DEFAULT_TARGET or None,
                   help="Process name or executable path")
    p.add_argument(
        "--mode",
        choices=sorted(MODES.keys()),
        default=None,
        help="Monitoring mode: full | connections | packets | light",
    )
    p.add_argument("-o", "--outbound-only", action="store_true",
                   default=cfg.OUTBOUND_ONLY,
                   help="Only analyze outbound connections")
    p.add_argument("--packets", action="store_true",
                   help="Force-enable packet capture for this run")
    p.add_argument("--no-packets", action="store_true",
                   help="Force-disable packet capture for this run")
    p.add_argument("--menu", action="store_true",
                   help="Show interactive mode menu")
    p.add_argument("--no-elevate-prompt", action="store_true",
                   help="Do not ask to relaunch as Administrator")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    if args.menu or (not args.app and args.mode is None and sys.stdin.isatty()):
        # Interactive path when no app given, or --menu
        if args.menu or not args.app:
            target, mode, outbound = interactive_menu()
            if not target:
                print("No target specified.", file=sys.stderr)
                sys.exit(1)
            args.app = target
            args.mode = mode
            args.outbound_only = outbound

    if cfg.WARN_IF_NOT_ADMIN:
        ensure_admin_warning(offer_elevation=cfg.OFFER_ELEVATION and not args.no_elevate_prompt)

    target = (args.app or "").strip()
    if not target:
        target = input("Application name or executable path: ").strip()
    if not target:
        print("No target specified.", file=sys.stderr)
        sys.exit(1)

    mode = args.mode or "full"
    runtime = apply_mode(mode)
    if args.packets:
        runtime["packets"] = True
    if args.no_packets:
        runtime["packets"] = False

    # Temporary override config flag used by packet module
    if runtime["packets"]:
        cfg.ENABLE_PACKET_CAPTURE = True
    else:
        cfg.ENABLE_PACKET_CAPTURE = False

    cfg.LOG_DIR.mkdir(parents=True, exist_ok=True)

    _print("=" * 78, "cyan")
    _print("  BEHAVIOR ANALYZER", "cyan")
    _print(f"  {cfg.TOOL_SIGNATURE}", "cyan")
    _print(f"  Target     : {target}")
    _print(f"  Mode       : {mode}")
    _print(f"  Admin      : {is_admin()}")
    _print(f"  Logs       : {cfg.LOG_DIR.resolve()}")
    _print(
        "  Features   : "
        f"proc={runtime['process']} files={runtime['files']} "
        f"reg={runtime['registry']} dns={runtime['dns']} "
        f"packets={runtime['packets']} mem={runtime['memory']}",
        "cyan",
    )
    if runtime["packets"]:
        _print("  Npcap      : required — https://npcap.com/", "yellow")
    _print("  Stop       : Ctrl+C  (auto-report on exit)", "cyan")
    _print("=" * 78, "cyan")

    analyzer = BehaviorAnalyzer(target, outbound_only=args.outbound_only, runtime=runtime)
    analyzer.start_side_channels()
    analyzer.bus.emit(BehaviorEvent(
        category="system",
        action="monitor_start",
        summary=f"Started behavior monitor for '{target}' (mode={mode})",
        details={"admin": is_admin(), "mode": mode, "runtime": runtime},
    ))

    try:
        while True:
            if cfg.PACKET_SNIFF_TIMEOUT and runtime["packets"]:
                if time.time() - analyzer._start_epoch >= cfg.PACKET_SNIFF_TIMEOUT:
                    _print(
                        f"[!] PACKET_SNIFF_TIMEOUT ({cfg.PACKET_SNIFF_TIMEOUT}s) reached — stopping",
                        "yellow",
                    )
                    break
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
            if runtime["packets"]:
                _print(f"[+] Packet log     : {cfg.PACKET_LOG_FILE.resolve()}", "green")
                _print(f"[+] PCAP file      : {cfg.PACKET_PCAP_FILE.resolve()}", "green")
                _print(f"[+] Packets kept   : {analyzer.packets.packet_count}", "green")
        shutdown_dns_pool()


if __name__ == "__main__":
    main()
