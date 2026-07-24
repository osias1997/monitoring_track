#!/usr/bin/env python3
"""
CLI monitor for TCP/UDP connections of a running application.
Requires: pip install psutil colorama
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from colorama import Fore, Style, init as colorama_init

from monitor_core import scan_processes, shutdown_dns_pool

LOG_FILE = Path("app_connections.log")
POLL_INTERVAL = 1.0


def status_color(status: str, direction: str) -> str:
    s = status.upper()
    if s == "ESTABLISHED":
        return Fore.GREEN
    if s == "LISTEN":
        return Fore.CYAN
    if direction == "outbound":
        return Fore.YELLOW
    return Fore.WHITE


def log_line(text: str, color: str = "") -> None:
    if color:
        print(f"{color}{text}{Style.RESET_ALL}")
    else:
        print(text)
    with LOG_FILE.open("a", encoding="utf-8") as fh:
        fh.write(text + "\n")


def format_line(rec: dict) -> str:
    return (
        f"[{rec['timestamp']}]  {rec['process']} (PID {rec['pid']})  |  "
        f"{rec['protocol']}  |  {rec['status']:<12}  |  {rec['direction']:<8}  |  "
        f"{rec['local']}  ->  {rec['remote']}"
    )


def monitor(target: str, outbound_only: bool) -> None:
    colorama_init(autoreset=True)
    seen: set[tuple] = set()
    remote_contacts: set[str] = set()

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
            processes, new_conns, new_remotes = scan_processes(target, outbound_only, seen)
            remote_contacts |= new_remotes

            if not processes:
                print(
                    f"{Fore.RED}No running process matching '{target}'. "
                    f"Waiting...{Style.RESET_ALL}",
                    end="\r",
                )
            else:
                for rec in new_conns:
                    log_line(
                        format_line(rec),
                        color=status_color(rec["status"], rec["direction"]),
                    )

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n{Fore.MAGENTA}Stopping monitor...{Style.RESET_ALL}")
    finally:
        shutdown_dns_pool()
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
