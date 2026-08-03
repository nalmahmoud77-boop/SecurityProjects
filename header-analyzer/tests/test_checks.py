"""Unit tests for the header checks and grading logic.

These run fully offline — no network required — by feeding synthetic header
dictionaries straight into the checks.
"""

from header_analyzer.checks import (
    check_cookies,
    check_csp,
    check_hsts,
    check_referrer_policy,
    check_x_content_type_options,
    run_all,
)
from header_analyzer.grading import grade, score, summarize


def test_missing_hsts_fails():
    finding = check_hsts({})
    assert not finding.ok
    assert finding.status == "fail"
    assert "max-age" in finding.remediation


def test_short_hsts_warns():
    finding = check_hsts({"Strict-Transport-Security": "max-age=3600"})
    assert finding.present
    assert not finding.ok
    assert finding.status == "warn"


def test_strong_hsts_passes():
    finding = check_hsts(
        {"Strict-Transport-Security": "max-age=63072000; includeSubDomains"}
    )
    assert finding.ok


def test_csp_with_unsafe_inline_warns():
    finding = check_csp({"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"})
    assert finding.present
    assert not finding.ok
    assert "unsafe-inline" in finding.detail


def test_nosniff_passes():
    finding = check_x_content_type_options({"X-Content-Type-Options": "nosniff"})
    assert finding.ok


def test_cookie_missing_flags_warns():
    finding = check_cookies({"Set-Cookie": "session=abc; Path=/"})
    assert not finding.ok
    assert "HttpOnly" in finding.detail


def test_cookie_with_all_flags_passes():
    finding = check_cookies(
        {"Set-Cookie": "session=abc; HttpOnly; Secure; SameSite=Lax"}
    )
    assert finding.ok


def test_referrer_policy_comma_list_uses_last_token():
    # Browsers apply the last recognized token; a safe fallback should pass.
    finding = check_referrer_policy(
        {"Referrer-Policy": "origin-when-cross-origin, strict-origin-when-cross-origin"}
    )
    assert finding.ok


def test_case_insensitive_header_lookup():
    # Header names are case-insensitive per RFC 7230.
    finding = check_x_content_type_options({"x-content-type-options": "nosniff"})
    assert finding.ok


def test_grade_boundaries():
    assert grade(100) == "A"
    assert grade(90) == "A"
    assert grade(89) == "B"
    assert grade(59) == "F"


def test_score_is_clamped():
    findings = run_all({})  # everything missing
    value = score(findings)
    assert 0 <= value <= 100


def test_perfect_headers_score_high():
    headers = {
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), camera=()",
    }
    findings = run_all(headers)
    value, letter, counts = summarize(findings)
    assert letter in ("A", "B")
    assert counts["fail"] == 0
