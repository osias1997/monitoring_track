#!/usr/bin/env python3
"""
Monitor TCP/UDP connections for one or more processes matching an app name/path.
Requires: pip install psutil colorama
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime
from pathlib import Path

import psutil
from colorama import Fore, Style, init as colorama_init

LOG_FILE = Path("app_connections.log")
POLL_INTERVAL = 1.0  # seconds between connection scans
HOSTNAME_TIMEOUT = 1.0  # seconds for reverse DNS

# Shared executor so reverse-DNS lookups don't block the main loop forever
_dns_pool = ThreadPoolExecutor(max_workers=4)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def resolve_hostname(ip: str) -> str | None:
    """Best-effort reverse DNS with a hard timeout. Returns None on failure."""
    if not ip or ip in ("0.0.0.0", "::", "*"):
        return None
    try:
        future = _dns_pool.submit(socket.gethostbyaddr, ip)
        name, _, _ = future.result(timeout=HOSTNAME_TIMEOUT)
        return name
    except (FuturesTimeout, socket.herror, socket.gaierror, OSError, ValueError):
        return None


def connection_key(pid: int, conn) -> tuple:
    """Unique identity for a connection so we only log it once when it appears."""
    laddr = (conn.laddr.ip, conn.laddr.port) if conn.laddr else (None, None)
    raddr = (conn.raddr.ip, conn.raddr.port) if conn.raddr else (None, None)
    return (pid, conn.type, conn.status, laddr, raddr)


def infer_direction(conn) -> str:
    """
    Heuristic direction:
    - LISTEN  -> inbound (waiting for clients)
    - no remote address -> local / listening-like
    - otherwise treat as outbound (process initiated or already connected)
    """
    status = (conn.status or "").upper()
    if status == "LISTEN":
        return "inbound"
    if not conn.raddr:
        return "local"
    # Ephemeral local ports (>1024) talking to a remote are typically outbound
    if conn.laddr and conn.laddr.port > 1024:
        return "outbound"
    return "inbound"


def format_endpoint(addr, resolve: bool = True) -> str:
    if not addr:
        return "*:*"
    host = addr.ip
    if resolve:
        name = resolve_hostname(host)
        if name:
            host = f"{name} ({addr.ip})"
    return f"{host}:{addr.port}"


def protocol_name(conn_type: int) -> str:
    if conn_type == socket.SOCK_STREAM:
        return "TCP"
    if conn_type == socket.SOCK_DGRAM:
        return "UDP"
    return str(conn_type)


def status_color(status: str, direction: str) -> str:
    s = status.upper()
    if s == "ESTABLISHED":
        return Fore.GREEN
    if s == "LISTEN":
        return Fore.CYAN
    if direction == "outbound":
        return Fore.YELLOW
    return Fore.WHITE


# ---------------------------------------------------------------------------
# Process discovery
# ---------------------------------------------------------------------------

def find_matching_pids(target: str) -> dict[int, str]:
    """
    Return {pid: process_name} for processes matching the given name or path.
    Matches basename (case-insensitive) and full executable path.
    """
    target_norm = target.replace("\\", "/").lower()
    target_base = Path(target).name.lower()
    matches: dict[int, str] = {}

    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            name = (proc.info["name"] or "").lower()
            exe = (proc.info["exe"] or "").replace("\\", "/").lower()
            if name == target_base or exe == target_norm or target_base in name:
                matches[proc.info["pid"]] = proc.info["name"] or name
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return matches


# ---------------------------------------------------------------------------
# Logging / display
# ---------------------------------------------------------------------------

def log_line(text: str, color: str = "") -> None:
    """Print to console (optionally colored) and append plain text to the log file."""
    timestamped = text  # already includes timestamp in message body
    if color:
        print(f"{color}{timestamped}{Style.RESET_ALL}")
    else:
        print(timestamped)
    with LOG_FILE.open("a", encoding="utf-8") as fh:
        fh.write(timestamped + "\n")


def format_connection_line(proc_name: str, pid: int, conn, direction: str) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    proto = protocol_name(conn.type)
    local = format_endpoint(conn.laddr, resolve=False)
    remote = format_endpoint(conn.raddr, resolve=True)
    status = conn.status or "NONE"
    return (
        f"[{ts}]  {proc_name} (PID {pid})  |  {proto}  |  {status:<12}  |  "
        f"{direction:<8}  |  {local}  ->  {remote}"
    )


# ---------------------------------------------------------------------------
# Main monitoring loop
# ---------------------------------------------------------------------------

def monitor(target: str, outbound_only: bool) -> None:
    colorama_init(autoreset=True)
    seen: set[tuple] = set()
    remote_contacts: set[str] = set()  # unique remotes for end summary

    header = (
        f"{'=' * 80}\n"
        f"  App Connection Monitor\n"
        f"  Target : {target}\n"
        f"  Filter : {'outbound only' if outbound_only else 'all connections'}\n"
        f"  Log    : {LOG_FILE.resolve()}\n"
        f"  Stop   : Ctrl+C\n"
        f"{'=' * 80}"
    )
    print(header)
    with LOG_FILE.open("a", encoding="utf-8") as fh:
        fh.write(header + "\n")

    try:
        while True:
            processes = find_matching_pids(target)
            if not processes:
                print(
                    f"{Fore.RED}No running process matching '{target}'. "
                    f"Waiting...{Style.RESET_ALL}",
                    end="\r",
                )
                time.sleep(POLL_INTERVAL)
                continue

            for pid, proc_name in processes.items():
                try:
                    proc = psutil.Process(pid)
                    # kind='inet' covers IPv4/IPv6 TCP + UDP
                    connections = proc.net_connections(kind="inet")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

                for conn in connections:
                    direction = infer_direction(conn)
                    if outbound_only and direction != "outbound":
                        continue

                    key = connection_key(pid, conn)
                    if key in seen:
                        continue
                    seen.add(key)

                    if conn.raddr:
                        remote_contacts.add(f"{conn.raddr.ip}:{conn.raddr.port}")

                    line = format_connection_line(proc_name, pid, conn, direction)
                    log_line(line, color=status_color(conn.status or "", direction))

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n{Fore.MAGENTA}Stopping monitor...{Style.RESET_ALL}")
    finally:
        _dns_pool.shutdown(wait=False)
        summary = [
            "",
            "=" * 80,
            "  SUMMARY",
            f"  Unique connections seen : {len(seen)}",
            f"  Unique remote endpoints : {len(remote_contacts)}",
        ]
        if remote_contacts:
            summary.append("  Remotes contacted:")
            for endpoint in sorted(remote_contacts):
                summary.append(f"    - {endpoint}")
        else:
            summary.append("  No remote endpoints recorded.")
        summary.append("=" * 80)
        block = "\n".join(summary)
        print(f"{Fore.CYAN}{block}{Style.RESET_ALL}")
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(block + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Monitor network connections for a running application."
    )
    parser.add_argument(
        "app",
        nargs="?",
        help="Process name (chrome, discord) or executable path. Prompted if omitted.",
    )
    parser.add_argument(
        "-o",
        "--outbound-only",
        action="store_true",
        help="Only log outbound connections.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    app = args.app or input("Application name or executable path: ").strip()
    if not app:
        print("No application specified. Exiting.", file=sys.stderr)
        sys.exit(1)
    monitor(app, outbound_only=args.outbound_only)


if __name__ == "__main__":
    main()
