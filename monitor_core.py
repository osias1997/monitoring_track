#!/usr/bin/env python3
"""
Shared helpers for process/connection discovery.
Used by the CLI monitor and the live web dashboard.
Requires: pip install psutil
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime
from pathlib import Path

import psutil

HOSTNAME_TIMEOUT = 1.0
_dns_pool = ThreadPoolExecutor(max_workers=4)


def resolve_hostname(ip: str) -> str | None:
    """Best-effort reverse DNS with a hard timeout."""
    if not ip or ip in ("0.0.0.0", "::", "*"):
        return None
    try:
        future = _dns_pool.submit(socket.gethostbyaddr, ip)
        name, _, _ = future.result(timeout=HOSTNAME_TIMEOUT)
        return name
    except (FuturesTimeout, socket.herror, socket.gaierror, OSError, ValueError):
        return None


def connection_key(pid: int, conn) -> tuple:
    laddr = (conn.laddr.ip, conn.laddr.port) if conn.laddr else (None, None)
    raddr = (conn.raddr.ip, conn.raddr.port) if conn.raddr else (None, None)
    return (pid, conn.type, conn.status, laddr, raddr)


def infer_direction(conn) -> str:
    status = (conn.status or "").upper()
    if status == "LISTEN":
        return "inbound"
    if not conn.raddr:
        return "local"
    if conn.laddr and conn.laddr.port > 1024:
        return "outbound"
    return "inbound"


def protocol_name(conn_type: int) -> str:
    if conn_type == socket.SOCK_STREAM:
        return "TCP"
    if conn_type == socket.SOCK_DGRAM:
        return "UDP"
    return str(conn_type)


def format_endpoint(addr, resolve: bool = True) -> str:
    if not addr:
        return "*:*"
    host = addr.ip
    if resolve:
        name = resolve_hostname(host)
        if name:
            host = f"{name} ({addr.ip})"
    return f"{host}:{addr.port}"


def find_matching_pids(target: str) -> dict[int, str]:
    """Return {pid: process_name} for processes matching name or path."""
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


def connection_record(proc_name: str, pid: int, conn, direction: str) -> dict:
    """Structured record for logging / web UI."""
    remote_ip = conn.raddr.ip if conn.raddr else None
    remote_port = conn.raddr.port if conn.raddr else None
    hostname = resolve_hostname(remote_ip) if remote_ip else None
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "process": proc_name,
        "pid": pid,
        "protocol": protocol_name(conn.type),
        "status": conn.status or "NONE",
        "direction": direction,
        "local": format_endpoint(conn.laddr, resolve=False),
        "remote": format_endpoint(conn.raddr, resolve=True),
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "hostname": hostname,
    }


def scan_processes(target: str, outbound_only: bool, seen: set) -> tuple[list[dict], list[dict], set[str]]:
    """
    One poll pass.
    Returns (process_list, new_connection_records, updated_remote_set_additions).
    """
    processes_out: list[dict] = []
    new_conns: list[dict] = []
    new_remotes: set[str] = set()

    matches = find_matching_pids(target)
    for pid, proc_name in matches.items():
        conn_count = 0
        try:
            proc = psutil.Process(pid)
            connections = proc.net_connections(kind="inet")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            processes_out.append(
                {"pid": pid, "name": proc_name, "connections": 0, "status": "inaccessible"}
            )
            continue

        for conn in connections:
            direction = infer_direction(conn)
            if outbound_only and direction != "outbound":
                continue
            conn_count += 1
            key = connection_key(pid, conn)
            if key in seen:
                continue
            seen.add(key)
            record = connection_record(proc_name, pid, conn, direction)
            new_conns.append(record)
            if conn.raddr:
                new_remotes.add(f"{conn.raddr.ip}:{conn.raddr.port}")

        processes_out.append(
            {"pid": pid, "name": proc_name, "connections": conn_count, "status": "running"}
        )

    processes_out.sort(key=lambda p: p["pid"])
    return processes_out, new_conns, new_remotes


def shutdown_dns_pool() -> None:
    _dns_pool.shutdown(wait=False)
