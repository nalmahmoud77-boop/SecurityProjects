"""Fingerprint a host's web stack from a single HTTP response.

The detection logic (``fingerprint_from``) is pure and operates on a headers
dict plus a snippet of HTML, so it is fully unit-testable offline. The network
call (``probe``) is a thin wrapper around it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests


@dataclass
class Fingerprint:
    """What we learned about one live web host."""

    url: str
    status_code: int = 0
    title: str = ""
    server: str = ""
    powered_by: str = ""
    technologies: List[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "title": self.title,
            "server": self.server,
            "powered_by": self.powered_by,
            "technologies": self.technologies,
            "error": self.error,
        }


# Signature table: technology name -> list of (source, compiled regex).
# "source" is one of: header name, "cookie", or "body".
def _sig(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


_SIGNATURES = {
    "WordPress": [("body", _sig(r"wp-content|wp-includes")), ("header:link", _sig(r"wp\.me"))],
    "Drupal": [("header:x-generator", _sig(r"drupal")), ("body", _sig(r"drupal"))],
    "Joomla": [("body", _sig(r"joomla"))],
    "Django": [("cookie", _sig(r"csrftoken|django")), ("header:x-frame-options", _sig(r"deny"))],
    "Flask": [("header:server", _sig(r"werkzeug"))],
    "Express": [("header:x-powered-by", _sig(r"express"))],
    "ASP.NET": [
        ("header:x-powered-by", _sig(r"asp\.net")),
        ("header:x-aspnet-version", _sig(r".+")),
        ("cookie", _sig(r"asp\.net_sessionid")),
    ],
    "PHP": [("header:x-powered-by", _sig(r"php")), ("cookie", _sig(r"phpsessid"))],
    "Laravel": [("cookie", _sig(r"laravel_session"))],
    "Ruby on Rails": [("header:x-powered-by", _sig(r"phusion|passenger")), ("cookie", _sig(r"_rails|_session_id"))],
    "Nginx": [("header:server", _sig(r"nginx"))],
    "Apache": [("header:server", _sig(r"apache"))],
    "IIS": [("header:server", _sig(r"iis|microsoft-httpapi"))],
    "Cloudflare": [("header:server", _sig(r"cloudflare")), ("header:cf-ray", _sig(r".+"))],
    "Varnish": [("header:via", _sig(r"varnish")), ("header:x-varnish", _sig(r".+"))],
    "React": [("body", _sig(r"react(dom)?[.-]|__reactroot"))],
    "Vue.js": [("body", _sig(r"vue(\.min)?\.js|data-v-"))],
    "Next.js": [("body", _sig(r"/_next/")), ("header:x-powered-by", _sig(r"next\.js"))],
}

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _header(headers: Dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value or ""
    return ""


def fingerprint_from(
    url: str,
    status_code: int,
    headers: Dict[str, str],
    body: str = "",
    cookies: str = "",
) -> Fingerprint:
    """Derive a Fingerprint from an already-fetched response."""
    server = _header(headers, "Server")
    powered = _header(headers, "X-Powered-By")

    title = ""
    match = _TITLE_RE.search(body or "")
    if match:
        title = re.sub(r"\s+", " ", match.group(1)).strip()[:120]

    detected: List[str] = []
    for tech, rules in _SIGNATURES.items():
        for source, rx in rules:
            haystack = ""
            if source == "body":
                haystack = body or ""
            elif source == "cookie":
                haystack = cookies or ""
            elif source.startswith("header:"):
                haystack = _header(headers, source.split(":", 1)[1])
            if haystack and rx.search(haystack):
                detected.append(tech)
                break

    return Fingerprint(
        url=url,
        status_code=status_code,
        title=title,
        server=server,
        powered_by=powered,
        technologies=sorted(set(detected)),
    )


def probe(
    hostname: str,
    timeout: int = 8,
    verify_tls: bool = True,
) -> Optional[Fingerprint]:
    """Fetch a host over HTTPS (falling back to HTTP) and fingerprint it.

    Returns None if neither scheme responds.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        try:
            response = requests.get(
                url,
                timeout=timeout,
                verify=verify_tls,
                allow_redirects=True,
                headers={"User-Agent": "recon-mapper"},
            )
        except requests.RequestException:
            continue

        cookie_str = "; ".join(
            f"{c.name}={c.value}" for c in response.cookies
        )
        # Include raw Set-Cookie names too, since some frameworks are only
        # visible there.
        set_cookie = _header(dict(response.headers), "Set-Cookie")
        body = response.text[:20000]  # cap to keep signature matching fast
        return fingerprint_from(
            url=response.url,
            status_code=response.status_code,
            headers=dict(response.headers),
            body=body,
            cookies=cookie_str + " " + set_cookie,
        )
    return None
