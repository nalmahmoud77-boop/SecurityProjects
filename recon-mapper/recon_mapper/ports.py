"""Lightweight concurrent TCP-connect port scanning.

This performs a plain TCP connect scan (no raw sockets, no root required):
for each port it attempts a connection and records whether it opened. It is
deliberately simple and is gated behind an explicit ``--ports`` flag because
port scanning is more intrusive than passive recon.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

from .wordlists import top_ports


def scan_port(host: str, port: int, timeout: float = 1.5) -> bool:
    """Return True if a TCP connection to ``host:port`` succeeds."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


def scan_host(
    host: str,
    ports: List[Tuple[int, str]],
    threads: int = 50,
    timeout: float = 1.5,
) -> List[Tuple[int, str]]:
    """Scan ``ports`` on a single host; return the open ones as (port, service)."""
    open_ports: List[Tuple[int, str]] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        future_map = {
            pool.submit(scan_port, host, port, timeout): (port, service)
            for port, service in ports
        }
        for future in as_completed(future_map):
            port, service = future_map[future]
            try:
                if future.result():
                    open_ports.append((port, service))
            except Exception:
                continue
    return sorted(open_ports)


def scan_top_ports(
    host: str,
    n: int = 20,
    threads: int = 50,
    timeout: float = 1.5,
) -> List[Tuple[int, str]]:
    """Scan the ``n`` most common ports on ``host``."""
    return scan_host(host, top_ports(n), threads=threads, timeout=timeout)
