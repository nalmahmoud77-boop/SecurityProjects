"""Thin DNS-resolution helpers built on the standard library.

We deliberately avoid a third-party DNS library: ``socket.getaddrinfo`` is
enough to answer the only question recon-mapper asks — "does this name resolve,
and to which addresses?".
"""

from __future__ import annotations

import socket
from typing import List


def resolve(hostname: str, timeout: float = 3.0) -> List[str]:
    """Resolve ``hostname`` to a sorted list of unique IP addresses.

    Returns an empty list if the name does not resolve. Both IPv4 and IPv6
    results are included.
    """
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, socket.herror, OSError):
        return []
    finally:
        socket.setdefaulttimeout(previous)

    addresses = {info[4][0] for info in infos}
    return sorted(addresses)


def is_valid_hostname(name: str) -> bool:
    """Cheap sanity check that a string looks like a DNS hostname."""
    if not name or len(name) > 253:
        return False
    if name.endswith("."):
        name = name[:-1]
    labels = name.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(c.isalnum() or c == "-" for c in label):
            return False
    return True
