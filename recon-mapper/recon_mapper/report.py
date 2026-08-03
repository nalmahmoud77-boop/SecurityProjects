"""Render a ReconResult as colored terminal text or JSON."""

from __future__ import annotations

import json

from .mapper import ReconResult

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_GREEN = "\033[32m"
_CYAN = "\033[36m"
_YELLOW = "\033[33m"


def to_json(result: ReconResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent)


def to_terminal(result: ReconResult, use_color: bool = True) -> str:
    def c(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if use_color else text

    lines = []
    lines.append("")
    lines.append(c("  Recon Report", _BOLD))
    lines.append(f"  Domain: {result.domain}")
    lines.append(
        f"  Surface: {len(result.hosts)} subdomain(s) discovered, "
        f"{len(result.live_hosts)} live"
    )
    lines.append("  " + "-" * 60)

    for host in result.hosts:
        if not host.is_live:
            lines.append(f"  {c('[-]', _DIM)} {c(host.hostname, _DIM)}  {c('(no DNS)', _DIM)}")
            continue

        lines.append(f"  {c('[+]', _GREEN)} {c(host.hostname, _BOLD)}")
        lines.append(f"      ip:   {', '.join(host.ips)}")

        fp = host.fingerprint
        if fp:
            lines.append(f"      http: {fp.status_code} {c(fp.title, _CYAN) if fp.title else ''}")
            if fp.server:
                lines.append(f"      server: {fp.server}")
            if fp.powered_by:
                lines.append(f"      x-powered-by: {fp.powered_by}")
            if fp.technologies:
                lines.append(f"      tech: {c(', '.join(fp.technologies), _YELLOW)}")
        else:
            lines.append(f"      {c('no web service responded', _DIM)}")

        if host.open_ports:
            ports = ", ".join(f"{p}/{s}" for p, s in host.open_ports)
            lines.append(f"      ports: {c(ports, _GREEN)}")
        lines.append("")

    return "\n".join(lines)
