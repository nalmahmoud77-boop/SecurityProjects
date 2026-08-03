"""Offline unit tests for recon-mapper's pure logic.

Network-dependent code (DNS, HTTP, crt.sh, port scanning) is exercised only
through its parsing/detection helpers, which take data in directly — so the
whole suite runs without touching the network.
"""

from recon_mapper.dns_utils import is_valid_hostname
from recon_mapper.fingerprint import fingerprint_from
from recon_mapper.mapper import HostReport, ReconResult
from recon_mapper.subdomains import parse_crtsh
from recon_mapper.wordlists import COMMON_PORTS, top_ports


# --- hostname validation ---------------------------------------------------

def test_valid_hostnames():
    assert is_valid_hostname("example.com")
    assert is_valid_hostname("api.dev.example.com")


def test_invalid_hostnames():
    assert not is_valid_hostname("")
    assert not is_valid_hostname("localhost")          # no dot
    assert not is_valid_hostname("-bad.example.com")   # label starts with -
    assert not is_valid_hostname("a..b.com")           # empty label


# --- crt.sh parsing --------------------------------------------------------

def test_parse_crtsh_extracts_in_scope_names():
    entries = [
        {"name_value": "www.example.com\n*.example.com"},
        {"name_value": "api.example.com"},
        {"name_value": "unrelated.org"},          # out of scope, dropped
    ]
    found = parse_crtsh(entries, "example.com")
    assert "www.example.com" in found
    assert "api.example.com" in found
    assert "example.com" in found                  # from the wildcard entry
    assert "unrelated.org" not in found


def test_parse_crtsh_handles_empty():
    assert parse_crtsh([], "example.com") == set()


# --- fingerprint detection -------------------------------------------------

def test_fingerprint_detects_server_and_powered_by():
    fp = fingerprint_from(
        url="https://x.example.com",
        status_code=200,
        headers={"Server": "nginx/1.25", "X-Powered-By": "PHP/8.2"},
        body="<html><title>Home</title></html>",
    )
    assert fp.server == "nginx/1.25"
    assert fp.title == "Home"
    assert "Nginx" in fp.technologies
    assert "PHP" in fp.technologies


def test_fingerprint_detects_wordpress_from_body():
    fp = fingerprint_from(
        url="https://blog.example.com",
        status_code=200,
        headers={},
        body='<link href="/wp-content/themes/x/style.css">',
    )
    assert "WordPress" in fp.technologies


def test_fingerprint_detects_framework_from_cookie():
    fp = fingerprint_from(
        url="https://app.example.com",
        status_code=200,
        headers={},
        cookies="laravel_session=abc; path=/",
    )
    assert "Laravel" in fp.technologies


def test_fingerprint_no_false_positive_on_plain_page():
    fp = fingerprint_from(
        url="https://plain.example.com",
        status_code=200,
        headers={"Server": ""},
        body="<html><body>hello</body></html>",
    )
    assert fp.technologies == []


# --- ports data ------------------------------------------------------------

def test_top_ports_slices_common_ports():
    assert top_ports(5) == COMMON_PORTS[:5]
    assert top_ports(0) == []
    assert len(top_ports(1000)) == len(COMMON_PORTS)


# --- result model ----------------------------------------------------------

def test_recon_result_summary():
    hosts = [
        HostReport("a.example.com", ips=["1.2.3.4"]),
        HostReport("b.example.com", ips=[]),           # not live
    ]
    result = ReconResult(domain="example.com", hosts=hosts)
    d = result.to_dict()
    assert d["summary"]["subdomains_found"] == 2
    assert d["summary"]["live_hosts"] == 1
    assert len(result.live_hosts) == 1
