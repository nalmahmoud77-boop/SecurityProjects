"""Turn a list of findings into a 0-100 score and an A-F letter grade."""

from __future__ import annotations

from typing import List, Tuple

from .checks import Finding, SEVERITY_WEIGHT


def score(findings: List[Finding]) -> int:
    """Compute a 0-100 score.

    Every control starts the site at 100 points. Each failing control removes
    points proportional to its severity; a present-but-weak control removes
    half. The result is clamped to the 0-100 range.
    """
    penalty = 0
    for finding in findings:
        if finding.ok:
            continue
        weight = SEVERITY_WEIGHT.get(finding.severity, 5)
        # A misconfigured-but-present header is less bad than a missing one.
        penalty += weight if not finding.present else weight // 2
    return max(0, min(100, 100 - penalty))


def grade(value: int) -> str:
    """Map a numeric score to a letter grade."""
    if value >= 90:
        return "A"
    if value >= 80:
        return "B"
    if value >= 70:
        return "C"
    if value >= 60:
        return "D"
    return "F"


def summarize(findings: List[Finding]) -> Tuple[int, str, dict]:
    """Return (score, grade, counts) for a set of findings."""
    counts = {"pass": 0, "warn": 0, "fail": 0}
    for finding in findings:
        counts[finding.status] += 1
    value = score(findings)
    return value, grade(value), counts
