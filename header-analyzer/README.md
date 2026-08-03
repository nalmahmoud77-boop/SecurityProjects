# 🛡️ Header Analyzer

> Audit any website's HTTP security headers, get a letter grade (A–F), and receive concrete, copy-paste remediation for every issue.

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/nalmahmoud77-boop/SecurityProjects/actions/workflows/ci.yml/badge.svg)](https://github.com/nalmahmoud77-boop/SecurityProjects/actions/workflows/ci.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-orange.svg)](CONTRIBUTING.md)

Header Analyzer is a small, focused security tool for web-app pen testers and developers. Point it at a URL and it inspects the response for the headers that matter — **CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy**, and cookie hardening flags — then grades the configuration and tells you exactly how to fix each gap.

```
  Security Header Report
  Target:  https://example.com
  Status:  HTTP 200
  Grade:   D  (62/100)
  Summary: 3 passed, 2 warnings, 3 failed
  ------------------------------------------------------------
  [FAIL] Content-Security-Policy  (critical)
        No CSP is set. CSP is the primary defense-in-depth control
        against cross-site scripting (XSS) and data-injection attacks.
        fix: Define a policy, e.g. Content-Security-Policy: default-src 'self'; ...

  [PASS] Strict-Transport-Security  (high)
        HSTS is enabled with an adequate max-age.
```

---

## ✨ Features

- **Letter-grade scoring** — a 0–100 score and an A–F grade weighted by severity, so you can see risk at a glance.
- **Actionable remediation** — every finding ships with a ready-to-use header value, not just "this is missing."
- **Three output formats** — colored terminal, machine-readable **JSON**, and a self-contained **HTML report** you can hand to a client.
- **CI-friendly** — `--fail-under` returns a non-zero exit code so you can gate deployments on a minimum score.
- **Smart checks** — understands that CSP `frame-ancestors` supersedes `X-Frame-Options`, flags weak CSP directives (`unsafe-inline`, wildcards), and audits `Set-Cookie` for `HttpOnly` / `Secure` / `SameSite`.
- **Zero-config & tiny** — one dependency (`requests`), fully tested, offline unit tests.

## 📦 Installation

```bash
# Clone the monorepo and enter this tool's folder
git clone https://github.com/nalmahmoud77-boop/SecurityProjects.git
cd SecurityProjects/header-analyzer

# (recommended) create a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install
pip install -e .
```

That installs a `header-analyzer` command. You can also run it without installing:

```bash
pip install -r requirements.txt
python -m header_analyzer.cli https://example.com
```

## 🚀 Usage

```bash
# Basic scan (terminal report)
header-analyzer https://example.com

# Hostname works too — https:// is assumed
header-analyzer example.com

# Save an HTML report to share
header-analyzer example.com --format html --output report.html

# Machine-readable JSON (pipe into jq, dashboards, etc.)
header-analyzer example.com --format json

# Fail a CI pipeline if the grade drops below 80
header-analyzer example.com --fail-under 80
```

### Options

| Flag | Description |
|------|-------------|
| `-f, --format {terminal,json,html}` | Output format (default: `terminal`) |
| `-o, --output FILE` | Write the report to a file instead of stdout |
| `--timeout N` | Request timeout in seconds (default: `10`) |
| `--no-color` | Disable ANSI colors |
| `--insecure` | Skip TLS certificate verification |
| `--fail-under SCORE` | Exit `1` if the score is below `SCORE` (for CI) |
| `--version` | Print version and exit |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed (and score ≥ `--fail-under` if set) |
| `1` | Score below `--fail-under` threshold |
| `2` | Network / TLS error reaching the target |

## 🔍 What it checks

| Control | Why it matters |
|---------|----------------|
| **Content-Security-Policy** | Primary defense against XSS and injection. Also flags weak directives. |
| **Strict-Transport-Security** | Forces HTTPS; prevents protocol-downgrade attacks. |
| **X-Frame-Options** | Blocks clickjacking via iframes (defers to CSP `frame-ancestors`). |
| **X-Content-Type-Options** | Stops MIME-sniffing that can turn uploads into XSS. |
| **Referrer-Policy** | Prevents leaking full URLs to third parties. |
| **Permissions-Policy** | Restricts powerful browser features (camera, geolocation, …). |
| **Cookie flags** | Audits `HttpOnly`, `Secure`, `SameSite` on `Set-Cookie`. |
| **Information disclosure** | Flags `Server` / `X-Powered-By` version leakage. |

## 🧪 Development & tests

```bash
pip install -e ".[dev]"
pytest -v
```

The test suite runs entirely offline — checks are fed synthetic header dictionaries, so no network access is required.

## 🗺️ Roadmap

- [ ] Scan a list of URLs from a file and emit a combined report
- [ ] Markdown output format
- [ ] Configurable scoring weights via a config file
- [ ] Optional cookie parsing of individual `Set-Cookie` entries
- [ ] GitHub Action wrapper

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## ⚖️ Legal & ethical use

> This tool sends a single HTTP GET request to a target you specify and reads the response headers. It performs **no exploitation, no fuzzing, and no authentication attacks.**

Even so, **only scan systems you own or are explicitly authorized to test.** Unauthorized scanning may violate computer-misuse laws and terms of service. You are responsible for how you use this software. It is provided for **authorized security testing and educational purposes only**, with no warranty (see [LICENSE](LICENSE)).

## 📄 License

Released under the [MIT License](LICENSE).
