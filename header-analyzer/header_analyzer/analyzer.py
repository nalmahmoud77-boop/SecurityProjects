"""Fetch a URL and run the security-header checks against the response."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

import requests

from . import __version__
from .checks import Finding, run_all
from .grading import summarize

DEFAULT_TIMEOUT = 10
USER_AGENT = f"header-analyzer/{__version__} (+https://github.com/)"


@dataclass
class AnalysisResult:
    """Everything the tool learned about one URL."""

    url: str
    final_url: str
    status_code: int
    score: int
    grade: str
    counts: Dict[str, int]
    findings: List[Finding]
    headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "score": self.score,
            "grade": self.grade,
            "counts": self.counts,
            "findings": [
                {
                    "name": f.name,
                    "status": f.status,
                    "severity": f.severity,
                    "present": f.present,
                    "value": f.value,
                    "detail": f.detail,
                    "remediation": f.remediation,
                    "references": f.references,
                }
                for f in self.findings
            ],
        }


def _normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def analyze(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    verify_tls: bool = True,
) -> AnalysisResult:
    """Request ``url`` and audit its response headers.

    Raises ``requests.RequestException`` on network failure so the caller can
    present a friendly error.
    """
    target = _normalize_url(url)
    response = requests.get(
        target,
        timeout=timeout,
        verify=verify_tls,
        allow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    )

    headers = dict(response.headers)
    findings = run_all(headers)
    value, letter, counts = summarize(findings)

    return AnalysisResult(
        url=target,
        final_url=response.url,
        status_code=response.status_code,
        score=value,
        grade=letter,
        counts=counts,
        findings=findings,
        headers=headers,
    )
