"""Subdomain enumeration — passive (certificate transparency) and active (DNS).

Passive discovery queries crt.sh, which indexes Certificate Transparency logs;
it finds real, previously-issued subdomains without sending a single packet to
the target. Active discovery brute-forces a wordlist against DNS. The two are
complementary and their results are merged and de-duplicated.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Set

import requests

from .dns_utils import resolve
from .wordlists import DEFAULT_SUBDOMAINS

CRTSH_URL = "https://crt.sh/"


def parse_crtsh(entries: Iterable[dict], domain: str) -> Set[str]:
    """Extract in-scope hostnames from crt.sh JSON rows.

    Split out from the network call so it can be unit-tested with sample data.
    Certificate ``name_value`` fields may contain multiple newline-separated
    names and wildcard (``*.``) entries.
    """
    found: Set[str] = set()
    suffix = domain.lower().lstrip(".")
    for entry in entries:
        raw = str(entry.get("name_value", ""))
        for name in raw.splitlines():
            name = name.strip().lower().lstrip("*.").rstrip(".")
            if not name:
                continue
            if name == suffix or name.endswith("." + suffix):
                found.add(name)
    return found


def from_crtsh(domain: str, timeout: int = 20) -> Set[str]:
    """Query crt.sh for certificates issued to ``domain`` and its subdomains."""
    try:
        response = requests.get(
            CRTSH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=timeout,
            headers={"User-Agent": "recon-mapper"},
        )
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError):
        return set()
    return parse_crtsh(data, domain)


def from_bruteforce(
    domain: str,
    words: List[str],
    threads: int = 40,
    timeout: float = 3.0,
) -> Set[str]:
    """Resolve ``word.domain`` for each word; keep the ones that resolve."""
    candidates = [f"{word.strip()}.{domain}" for word in words if word.strip()]
    live: Set[str] = set()

    with ThreadPoolExecutor(max_workers=threads) as pool:
        future_map = {
            pool.submit(resolve, host, timeout): host for host in candidates
        }
        for future in as_completed(future_map):
            host = future_map[future]
            try:
                if future.result():
                    live.add(host)
            except Exception:
                # A single failed lookup should never abort the sweep.
                continue
    return live


def enumerate_subdomains(
    domain: str,
    wordlist: List[str] | None = None,
    passive_only: bool = False,
    threads: int = 40,
    timeout: float = 3.0,
) -> List[str]:
    """Run passive + active discovery and return a sorted, de-duplicated list."""
    results: Set[str] = set()
    results |= from_crtsh(domain)

    if not passive_only:
        words = wordlist if wordlist is not None else DEFAULT_SUBDOMAINS
        results |= from_bruteforce(domain, words, threads=threads, timeout=timeout)

    # Always consider the bare domain itself part of the surface.
    results.add(domain.lower())
    return sorted(results)
