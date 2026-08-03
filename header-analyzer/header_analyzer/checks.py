"""Definitions and checks for HTTP security headers.

Each header check returns a ``Finding`` describing whether the header is
present, whether it is well configured, the severity of any problem, and a
concrete remediation string. Keeping the security knowledge in one place makes
the tool easy to extend: add a new function and register it in ``ALL_CHECKS``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List

# Severity weights are used by the grading module to compute a score. Higher
# weight means a missing/misconfigured header costs more points.
SEVERITY_WEIGHT = {
    "critical": 25,
    "high": 15,
    "medium": 10,
    "low": 5,
    "info": 0,
}


@dataclass
class Finding:
    """The result of auditing a single security control."""

    name: str
    present: bool
    ok: bool
    severity: str
    value: str = ""
    detail: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        if self.ok:
            return "pass"
        return "warn" if self.present else "fail"


def _get(headers: Dict[str, str], name: str) -> str:
    """Case-insensitive header lookup returning the raw value or ''."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


# --------------------------------------------------------------------------- #
# Individual header checks
# --------------------------------------------------------------------------- #


def check_hsts(headers: Dict[str, str]) -> Finding:
    value = _get(headers, "Strict-Transport-Security")
    ref = ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"]
    if not value:
        return Finding(
            name="Strict-Transport-Security",
            present=False,
            ok=False,
            severity="high",
            detail="HSTS is not set. Browsers may connect over plain HTTP, "
            "exposing users to protocol-downgrade and cookie-hijacking attacks.",
            remediation="Add: Strict-Transport-Security: max-age=63072000; "
            "includeSubDomains; preload",
            references=ref,
        )

    max_age = 0
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                max_age = 0

    if max_age < 15552000:  # 180 days
        return Finding(
            name="Strict-Transport-Security",
            present=True,
            ok=False,
            severity="medium",
            value=value,
            detail=f"HSTS max-age is {max_age}s, below the recommended 180 days.",
            remediation="Increase max-age to at least 63072000 (2 years) and add "
            "includeSubDomains.",
            references=ref,
        )

    return Finding(
        name="Strict-Transport-Security",
        present=True,
        ok=True,
        severity="high",
        value=value,
        detail="HSTS is enabled with an adequate max-age.",
        references=ref,
    )


def check_csp(headers: Dict[str, str]) -> Finding:
    value = _get(headers, "Content-Security-Policy")
    ref = ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy"]
    if not value:
        return Finding(
            name="Content-Security-Policy",
            present=False,
            ok=False,
            severity="critical",
            detail="No CSP is set. CSP is the primary defense-in-depth control "
            "against cross-site scripting (XSS) and data-injection attacks.",
            remediation="Define a policy, e.g. Content-Security-Policy: "
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
            references=ref,
        )

    weak = []
    lowered = value.lower()
    if "unsafe-inline" in lowered:
        weak.append("'unsafe-inline' allows inline scripts/styles")
    if "unsafe-eval" in lowered:
        weak.append("'unsafe-eval' permits eval()-style execution")
    if "default-src *" in lowered or "script-src *" in lowered:
        weak.append("wildcard source '*' allows loading from any origin")

    if weak:
        return Finding(
            name="Content-Security-Policy",
            present=True,
            ok=False,
            severity="medium",
            value=value,
            detail="CSP is present but weakened: " + "; ".join(weak) + ".",
            remediation="Remove unsafe-inline/unsafe-eval and wildcards; prefer "
            "nonces or hashes for inline scripts.",
            references=ref,
        )

    return Finding(
        name="Content-Security-Policy",
        present=True,
        ok=True,
        severity="critical",
        value=value,
        detail="A Content-Security-Policy is defined without obvious weaknesses.",
        references=ref,
    )


def check_x_frame_options(headers: Dict[str, str]) -> Finding:
    value = _get(headers, "X-Frame-Options")
    csp = _get(headers, "Content-Security-Policy").lower()
    ref = ["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options"]
    # frame-ancestors in CSP supersedes X-Frame-Options.
    if "frame-ancestors" in csp:
        return Finding(
            name="X-Frame-Options",
            present=bool(value),
            ok=True,
            severity="medium",
            value=value or "(covered by CSP frame-ancestors)",
            detail="Clickjacking protection is provided by CSP frame-ancestors.",
            references=ref,
        )
    if not value:
        return Finding(
            name="X-Frame-Options",
            present=False,
            ok=False,
            severity="medium",
            detail="Missing clickjacking protection. The page can be embedded in "
            "an attacker-controlled iframe.",
            remediation="Add: X-Frame-Options: DENY (or SAMEORIGIN if framing is needed).",
            references=ref,
        )
    if value.strip().upper() not in {"DENY", "SAMEORIGIN"}:
        return Finding(
            name="X-Frame-Options",
            present=True,
            ok=False,
            severity="low",
            value=value,
            detail=f"Unexpected value '{value}'. Only DENY and SAMEORIGIN are reliable.",
            remediation="Set X-Frame-Options to DENY or SAMEORIGIN.",
            references=ref,
        )
    return Finding(
        name="X-Frame-Options",
        present=True,
        ok=True,
        severity="medium",
        value=value,
        detail="Clickjacking protection is enabled.",
        references=ref,
    )


def check_x_content_type_options(headers: Dict[str, str]) -> Finding:
    value = _get(headers, "X-Content-Type-Options")
    ref = ["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"]
    if value.strip().lower() == "nosniff":
        return Finding(
            name="X-Content-Type-Options",
            present=True,
            ok=True,
            severity="medium",
            value=value,
            detail="MIME-type sniffing is disabled.",
            references=ref,
        )
    return Finding(
        name="X-Content-Type-Options",
        present=bool(value),
        ok=False,
        severity="medium",
        value=value,
        detail="MIME-sniffing is not disabled. Browsers may interpret responses "
        "as a different content type, enabling some XSS vectors.",
        remediation="Add: X-Content-Type-Options: nosniff",
        references=ref,
    )


def check_referrer_policy(headers: Dict[str, str]) -> Finding:
    value = _get(headers, "Referrer-Policy")
    ref = ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy"]
    safe = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    # A Referrer-Policy may be a comma-separated list; the browser applies the
    # last token it recognizes. Treat the policy as safe if that token is safe.
    tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
    effective = tokens[-1] if tokens else ""
    if effective in safe:
        return Finding(
            name="Referrer-Policy",
            present=True,
            ok=True,
            severity="low",
            value=value,
            detail="A privacy-preserving referrer policy is set.",
            references=ref,
        )
    return Finding(
        name="Referrer-Policy",
        present=bool(value),
        ok=False,
        severity="low",
        value=value,
        detail="No safe Referrer-Policy set. Full URLs may leak to third parties "
        "via the Referer header.",
        remediation="Add: Referrer-Policy: strict-origin-when-cross-origin",
        references=ref,
    )


def check_permissions_policy(headers: Dict[str, str]) -> Finding:
    value = _get(headers, "Permissions-Policy") or _get(headers, "Feature-Policy")
    ref = ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy"]
    if value:
        return Finding(
            name="Permissions-Policy",
            present=True,
            ok=True,
            severity="low",
            value=value,
            detail="A Permissions-Policy restricts access to powerful browser features.",
            references=ref,
        )
    return Finding(
        name="Permissions-Policy",
        present=False,
        ok=False,
        severity="low",
        detail="No Permissions-Policy set. Powerful features (camera, geolocation, "
        "etc.) are not explicitly restricted.",
        remediation="Add, e.g.: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        references=ref,
    )


def check_server_disclosure(headers: Dict[str, str]) -> Finding:
    server = _get(headers, "Server")
    powered = _get(headers, "X-Powered-By")
    ref = ["https://owasp.org/www-project-secure-headers/"]
    leaks = []
    if any(ch.isdigit() for ch in server):
        leaks.append(f"Server: {server}")
    if powered:
        leaks.append(f"X-Powered-By: {powered}")
    if leaks:
        return Finding(
            name="Information Disclosure",
            present=True,
            ok=False,
            severity="low",
            value="; ".join(leaks),
            detail="Response headers reveal software/version details that help an "
            "attacker fingerprint the stack.",
            remediation="Suppress or genericize Server and remove X-Powered-By headers.",
            references=ref,
        )
    return Finding(
        name="Information Disclosure",
        present=False,
        ok=True,
        severity="low",
        detail="No obvious version/stack disclosure in headers.",
        references=ref,
    )


def check_cookies(headers: Dict[str, str]) -> Finding:
    # requests lowercases and joins duplicate Set-Cookie headers with ', ' — good
    # enough for a flag audit. We look at each cookie's attributes.
    raw = _get(headers, "Set-Cookie")
    ref = ["https://owasp.org/www-community/controls/SecureCookieAttribute"]
    if not raw:
        return Finding(
            name="Cookie Flags",
            present=False,
            ok=True,
            severity="medium",
            detail="No cookies were set on this response.",
            references=ref,
        )

    lowered = raw.lower()
    missing = []
    if "httponly" not in lowered:
        missing.append("HttpOnly (blocks JavaScript access, mitigates XSS theft)")
    if "secure" not in lowered:
        missing.append("Secure (ensures cookie is only sent over HTTPS)")
    if "samesite" not in lowered:
        missing.append("SameSite (mitigates CSRF)")

    if missing:
        return Finding(
            name="Cookie Flags",
            present=True,
            ok=False,
            severity="medium",
            value=raw[:120] + ("..." if len(raw) > 120 else ""),
            detail="Set-Cookie is missing hardening flags: " + "; ".join(missing) + ".",
            remediation="Set every session cookie with: HttpOnly; Secure; SameSite=Lax (or Strict).",
            references=ref,
        )
    return Finding(
        name="Cookie Flags",
        present=True,
        ok=True,
        severity="medium",
        value=raw[:120] + ("..." if len(raw) > 120 else ""),
        detail="Cookies carry HttpOnly, Secure, and SameSite attributes.",
        references=ref,
    )


# Registry consumed by the analyzer. Add new checks here.
ALL_CHECKS: List[Callable[[Dict[str, str]], Finding]] = [
    check_csp,
    check_hsts,
    check_x_frame_options,
    check_x_content_type_options,
    check_referrer_policy,
    check_permissions_policy,
    check_cookies,
    check_server_disclosure,
]


def run_all(headers: Dict[str, str]) -> List[Finding]:
    """Run every registered check against a header dictionary."""
    return [check(headers) for check in ALL_CHECKS]
