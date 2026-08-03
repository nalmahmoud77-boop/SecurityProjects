"""Orchestrate a full recon run and assemble a consolidated result object."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .dns_utils import resolve
from .fingerprint import Fingerprint, probe
from .ports import scan_top_ports
from .subdomains import enumerate_subdomains


@dataclass
class HostReport:
    """Everything discovered about a single host."""

    hostname: str
    ips: List[str] = field(default_factory=list)
    fingerprint: Optional[Fingerprint] = None
    open_ports: List = field(default_factory=list)

    @property
    def is_live(self) -> bool:
        return bool(self.ips)

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "ips": self.ips,
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else None,
            "open_ports": [{"port": p, "service": s} for p, s in self.open_ports],
        }


@dataclass
class ReconResult:
    domain: str
    hosts: List[HostReport] = field(default_factory=list)

    @property
    def live_hosts(self) -> List[HostReport]:
        return [h for h in self.hosts if h.is_live]

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "summary": {
                "subdomains_found": len(self.hosts),
                "live_hosts": len(self.live_hosts),
            },
            "hosts": [h.to_dict() for h in self.hosts],
        }


def run_recon(
    domain: str,
    wordlist: Optional[List[str]] = None,
    passive_only: bool = False,
    scan_ports: bool = False,
    top_ports_count: int = 20,
    threads: int = 40,
    timeout: float = 3.0,
    verify_tls: bool = True,
    progress: Optional[Callable[[str], None]] = None,
) -> ReconResult:
    """Enumerate, resolve, fingerprint (and optionally port-scan) ``domain``.

    ``progress`` is an optional callback for status messages so the CLI can
    show what stage it is in.
    """
    def note(msg: str) -> None:
        if progress:
            progress(msg)

    note(f"Enumerating subdomains for {domain} ...")
    names = enumerate_subdomains(
        domain,
        wordlist=wordlist,
        passive_only=passive_only,
        threads=threads,
        timeout=timeout,
    )
    note(f"Found {len(names)} candidate name(s). Resolving ...")

    hosts = [HostReport(hostname=name) for name in names]

    # Resolve all names concurrently to find the live ones.
    with ThreadPoolExecutor(max_workers=threads) as pool:
        future_map = {pool.submit(resolve, h.hostname, timeout): h for h in hosts}
        for future in as_completed(future_map):
            host = future_map[future]
            try:
                host.ips = future.result()
            except Exception:
                host.ips = []

    live = [h for h in hosts if h.is_live]
    note(f"{len(live)} host(s) resolve. Fingerprinting web services ...")

    # Fingerprint live hosts over HTTP(S), concurrently.
    with ThreadPoolExecutor(max_workers=min(threads, 20)) as pool:
        future_map = {
            pool.submit(probe, h.hostname, 8, verify_tls): h for h in live
        }
        for future in as_completed(future_map):
            host = future_map[future]
            try:
                host.fingerprint = future.result()
            except Exception:
                host.fingerprint = None

    if scan_ports:
        note(f"Scanning top {top_ports_count} ports on {len(live)} live host(s) ...")
        for host in live:
            target = host.ips[0]
            host.open_ports = scan_top_ports(target, n=top_ports_count, timeout=1.5)

    note("Done.")
    return ReconResult(domain=domain, hosts=hosts)
