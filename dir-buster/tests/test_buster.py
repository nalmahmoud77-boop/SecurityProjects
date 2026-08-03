"""Offline unit tests for dir-buster's pure logic (no network required)."""

from dir_buster.core import (
    Filter,
    Finding,
    ScanResult,
    generate_candidates,
    join_url,
    looks_like_dir,
    matches_baseline,
    normalize_base_url,
    normalize_extensions,
)


# --- extensions ------------------------------------------------------------

def test_normalize_extensions_adds_dot_and_dedupes():
    assert normalize_extensions(["php", ".html", "php"]) == [".php", ".html"]
    assert normalize_extensions(None) == []
    assert normalize_extensions([" ", ""]) == []


# --- candidate generation --------------------------------------------------

def test_generate_candidates_basic():
    out = list(generate_candidates(["admin", "login"]))
    assert out == ["admin", "login"]


def test_generate_candidates_with_extensions():
    out = list(generate_candidates(["index"], ["php", "html"]))
    assert out == ["index", "index.php", "index.html"]


def test_generate_candidates_skips_comments_blanks_and_dedupes():
    words = ["# comment", "", "admin", "admin", "/api"]
    out = list(generate_candidates(words))
    assert out == ["admin", "api"]           # comment/blank skipped, / stripped, deduped


# --- url helpers -----------------------------------------------------------

def test_join_url_single_slash():
    assert join_url("http://x.com", "admin") == "http://x.com/admin"
    assert join_url("http://x.com/", "/admin") == "http://x.com/admin"


def test_normalize_base_url_adds_scheme_and_strips_slash():
    assert normalize_base_url("example.com/") == "http://example.com"
    assert normalize_base_url("https://x.com") == "https://x.com"


# --- directory heuristic ---------------------------------------------------

def test_looks_like_dir():
    assert looks_like_dir(301, "http://x.com/admin/")
    assert not looks_like_dir(301, "http://x.com/admin")   # no trailing slash
    assert not looks_like_dir(200, "")                     # not a redirect


# --- soft-404 calibration matching ----------------------------------------

def test_matches_baseline_within_tolerance():
    baselines = {(200, 1000)}
    assert matches_baseline(200, 1004, baselines, tolerance=8)     # close size
    assert not matches_baseline(200, 1100, baselines, tolerance=8) # too different
    assert not matches_baseline(404, 1000, baselines, tolerance=8) # different status


# --- filtering -------------------------------------------------------------

def test_filter_default_hides_404():
    flt = Filter()
    assert flt.passes(200, 500)
    assert not flt.passes(404, 500)


def test_filter_match_codes_whitelist():
    flt = Filter(match_codes={200, 301})
    assert flt.passes(200, 10)
    assert flt.passes(301, 10)
    assert not flt.passes(403, 10)


def test_filter_sizes():
    flt = Filter(filter_sizes={0, 1234})
    assert not flt.passes(200, 0)
    assert not flt.passes(200, 1234)
    assert flt.passes(200, 500)


# --- result model ----------------------------------------------------------

def test_scan_result_to_dict_sorted():
    result = ScanResult(base_url="http://x.com", requests_made=10)
    result.findings.append(Finding("login", "http://x.com/login", 200, 100))
    result.findings.append(Finding("admin", "http://x.com/admin", 301, 0, is_dir=True))
    d = result.to_dict()
    assert d["summary"]["requests_made"] == 10
    assert d["summary"]["findings"] == 2
    # sorted by path -> admin before login
    assert [f["path"] for f in d["findings"]] == ["admin", "login"]
