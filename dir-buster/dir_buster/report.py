"""Render a ScanResult as a colored terminal table or JSON."""

from __future__ import annotations

import json

from .core import ScanResult

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

# Colorize by status-code class.
def _status_color(status: int) -> str:
    if 200 <= status < 300:
        return "\033[32m"  # green
    if 300 <= status < 400:
        return "\033[36m"  # cyan
    if status in (401, 403):
        return "\033[33m"  # yellow
    if 400 <= status < 500:
        return "\033[31m"  # red
    return "\033[35m"      # magenta (5xx)


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent)


def to_terminal(result: ScanResult, use_color: bool = True) -> str:
    def c(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if use_color else text

    lines = []
    lines.append("")
    lines.append(c("  Content Discovery Report", _BOLD))
    lines.append(f"  Target:   {result.base_url}")
    lines.append(
        f"  Requests: {result.requests_made}   Findings: {len(result.findings)}"
    )
    lines.append("  " + "-" * 62)

    if not result.findings:
        lines.append(c("  (no paths matched the filters)", _DIM))
        return "\n".join(lines)

    lines.append(
        c(f"  {'STATUS':<7} {'SIZE':>8}  {'TYPE':<16} PATH", _DIM)
    )
    for f in result.sorted_findings():
        status_str = c(f"{f.status:<7}", _status_color(f.status) if use_color else "")
        marker = "/" if f.is_dir else ""
        ctype = (f.content_type or "")[:16]
        row = f"  {status_str} {f.length:>8}  {ctype:<16} {f.path}{marker}"
        if f.redirect:
            row += c(f"  -> {f.redirect}", _DIM)
        lines.append(row)

    return "\n".join(lines)
