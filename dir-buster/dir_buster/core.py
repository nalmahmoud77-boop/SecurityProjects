"""Pure, network-free logic: candidate generation, filtering, and data models.

Everything here is deterministic and unit-tested offline. The network layer in
``scanner.py`` builds on top of these helpers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Iterator, List, Optional, Set, Tuple

# HTTP status codes that indicate a path is a directory (redirect to trailing /)
_REDIRECT_CODES = {301, 302, 307, 308}


def normalize_extensions(extensions: Optional[Iterable[str]]) -> List[str]:
    """Normalize a list of extensions to a clean, dot-prefixed form."""
    out: List[str] = []
    for ext in extensions or []:
        ext = ext.strip()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = "." + ext
        if ext not in out:
            out.append(ext)
    return out


def generate_candidates(
    words: Iterable[str],
    extensions: Optional[Iterable[str]] = None,
) -> Iterator[str]:
    """Yield de-duplicated path candidates from words (+ optional extensions).

    Blank lines and ``#`` comments are skipped. A leading ``/`` on a word is
    stripped so paths join cleanly onto a base URL.
    """
    exts = normalize_extensions(extensions)
    seen: Set[str] = set()
    for word in words:
        word = word.strip()
        if not word or word.startswith("#"):
            continue
        word = word.lstrip("/")
        for candidate in [word] + [word + ext for ext in exts]:
            if candidate not in seen:
                seen.add(candidate)
                yield candidate


def join_url(base: str, path: str) -> str:
    """Join a base URL and a path with exactly one slash between them."""
    return base.rstrip("/") + "/" + path.lstrip("/")


def normalize_base_url(url: str) -> str:
    """Ensure a scheme is present and drop any trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def looks_like_dir(status: int, redirect_location: str) -> bool:
    """Heuristic: a redirect to a trailing-slash location means a directory."""
    return status in _REDIRECT_CODES and redirect_location.endswith("/")


def matches_baseline(
    status: int,
    length: int,
    baselines: Iterable[Tuple[int, int]],
    tolerance: int = 8,
) -> bool:
    """Return True if (status, length) resembles a calibrated soft-404 baseline.

    ``baselines`` is a set of (status, content_length) pairs captured from
    requests to paths known not to exist. A tolerance absorbs pages whose size
    varies slightly (e.g. an echoed path in the body).
    """
    for b_status, b_length in baselines:
        if status == b_status and abs(length - b_length) <= tolerance:
            return True
    return False


@dataclass
class Filter:
    """Decides whether a probed response is worth reporting."""

    match_codes: Optional[Set[int]] = None
    filter_codes: Set[int] = field(default_factory=lambda: {404})
    filter_sizes: Set[int] = field(default_factory=set)

    def passes(self, status: int, length: int) -> bool:
        if self.match_codes is not None and status not in self.match_codes:
            return False
        if status in self.filter_codes:
            return False
        if length in self.filter_sizes:
            return False
        return True


@dataclass
class Finding:
    """A single interesting path discovered during a scan."""

    path: str
    url: str
    status: int
    length: int
    words: int = 0
    lines: int = 0
    redirect: str = ""
    content_type: str = ""
    is_dir: bool = False

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "url": self.url,
            "status": self.status,
            "length": self.length,
            "words": self.words,
            "lines": self.lines,
            "redirect": self.redirect,
            "content_type": self.content_type,
            "is_dir": self.is_dir,
        }


@dataclass
class ScanResult:
    base_url: str
    findings: List[Finding] = field(default_factory=list)
    requests_made: int = 0

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (f.path))

    def to_dict(self) -> dict:
        return {
            "base_url": self.base_url,
            "summary": {
                "requests_made": self.requests_made,
                "findings": len(self.findings),
            },
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
