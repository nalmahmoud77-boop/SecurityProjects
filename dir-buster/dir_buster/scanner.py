"""The network engine: probing, soft-404 calibration, and the scan loop.

Concurrency uses a thread pool (I/O-bound work). Recursion is handled with a
work queue of (base_url, depth) so discovered directories are scanned in turn.
"""

from __future__ import annotations

import random
import string
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional, Set, Tuple

import requests

from .core import (
    Filter,
    Finding,
    ScanResult,
    generate_candidates,
    join_url,
    looks_like_dir,
    matches_baseline,
    normalize_base_url,
)

USER_AGENT = "dir-buster"


def _measure(response: requests.Response) -> Tuple[int, int, int]:
    """Return (content_length, word_count, line_count) for a response."""
    body = response.content
    length = len(body)
    try:
        text = response.text
        words = len(text.split())
        lines = text.count("\n")
    except Exception:
        words = lines = 0
    return length, words, lines


def probe(
    session: requests.Session,
    url: str,
    timeout: float,
    verify_tls: bool,
) -> Optional[Tuple[int, int, int, int, str, str]]:
    """Request ``url`` without following redirects.

    Returns (status, length, words, lines, redirect_location, content_type) or
    None on a network error.
    """
    try:
        response = session.get(
            url,
            timeout=timeout,
            verify=verify_tls,
            allow_redirects=False,
        )
    except requests.RequestException:
        return None
    length, words, lines = _measure(response)
    return (
        response.status_code,
        length,
        words,
        lines,
        response.headers.get("Location", ""),
        response.headers.get("Content-Type", "").split(";")[0].strip(),
    )


def calibrate(
    session: requests.Session,
    base_url: str,
    timeout: float,
    verify_tls: bool,
    samples: int = 3,
) -> Set[Tuple[int, int]]:
    """Probe random non-existent paths to learn this directory's soft-404 shape.

    Sites that return 200 (or a fixed-size 404 page) for everything would
    otherwise flood the output. We record (status, length) of those responses
    so the scan can filter matching results.
    """
    baselines: Set[Tuple[int, int]] = set()
    for _ in range(samples):
        rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        result = probe(session, join_url(base_url, rand), timeout, verify_tls)
        if result is None:
            continue
        status, length = result[0], result[1]
        baselines.add((status, length))
    return baselines


def run_scan(
    target: str,
    words: List[str],
    extensions: Optional[List[str]] = None,
    threads: int = 30,
    timeout: float = 8.0,
    delay: float = 0.0,
    recursive: bool = False,
    max_depth: int = 2,
    filter_config: Optional[Filter] = None,
    verify_tls: bool = True,
    progress: Optional[Callable[[str], None]] = None,
) -> ScanResult:
    """Run a (optionally recursive) content-discovery scan against ``target``."""
    def note(msg: str) -> None:
        if progress:
            progress(msg)

    base = normalize_base_url(target)
    flt = filter_config or Filter()
    candidates = list(generate_candidates(words, extensions))

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    result = ScanResult(base_url=base)
    queue: List[Tuple[str, int]] = [(base, 0)]
    scanned_dirs: Set[str] = set()

    while queue:
        current_base, depth = queue.pop(0)
        if current_base in scanned_dirs:
            continue
        scanned_dirs.add(current_base)

        note(f"Scanning {current_base}/  ({len(candidates)} candidates, depth {depth})")
        baselines = calibrate(session, current_base, timeout, verify_tls)

        def work(path: str):
            if delay > 0:
                time.sleep(delay)
            url = join_url(current_base, path)
            probed = probe(session, url, timeout, verify_tls)
            return path, url, probed

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [pool.submit(work, path) for path in candidates]
            for future in as_completed(futures):
                path, url, probed = future.result()
                result.requests_made += 1
                if probed is None:
                    continue
                status, length, words_n, lines_n, location, ctype = probed

                if not flt.passes(status, length):
                    continue
                if matches_baseline(status, length, baselines):
                    continue

                is_dir = looks_like_dir(status, location)
                result.findings.append(
                    Finding(
                        path=path,
                        url=url,
                        status=status,
                        length=length,
                        words=words_n,
                        lines=lines_n,
                        redirect=location,
                        content_type=ctype,
                        is_dir=is_dir,
                    )
                )

                if recursive and is_dir and depth + 1 <= max_depth:
                    child = url.rstrip("/")
                    if child not in scanned_dirs:
                        queue.append((child, depth + 1))

    note(f"Done. {result.requests_made} requests, {len(result.findings)} findings.")
    return result
