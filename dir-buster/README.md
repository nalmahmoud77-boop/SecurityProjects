# 📂 dir-buster

> Discover hidden directories and files on a web server — a focused content-discovery tool with concurrency, recursion, and automatic soft-404 filtering to cut false positives.

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/nalmahmoud77-boop/SecurityProjects/actions/workflows/ci.yml/badge.svg)](https://github.com/nalmahmoud77-boop/SecurityProjects/actions/workflows/ci.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-orange.svg)](CONTRIBUTING.md)

`dir-buster` brute-forces paths against a target from a wordlist to find content that isn't linked anywhere — admin panels, backups, API endpoints, config files. It's built around **accuracy**: before scanning each directory it calibrates against random non-existent paths, so servers that return `200` for everything (soft-404s) don't flood your results.

```
  Content Discovery Report
  Target:   https://example.com
  Requests: 148   Findings: 4
  --------------------------------------------------------------
  STATUS   SIZE   TYPE             PATH
  200        1256  text/html        index.html
  301           0  text/html        admin/  -> https://example.com/admin/
  403         279  text/html        .git/
  200         842  application/json  api/v1
```

---

## ✨ Features

- **Concurrent scanning** — a configurable thread pool keeps it fast.
- **Soft-404 calibration** — samples random paths per directory and filters responses that match the "not found" fingerprint (status + size), killing false positives that trip up naïve scanners.
- **Recursion** — automatically descends into discovered directories (`-r`, with `--max-depth`).
- **Extension expansion** — append extensions to every word (`-x php,html,txt`, or `-x common` for a built-in set).
- **Flexible filtering** — match/hide by status code (`-mc`, `-fc`) and hide by exact response size (`-fs`).
- **Rate limiting** — add a per-request delay (`--delay`) to be gentle on a target.
- **Clean output** — colored terminal table or machine-readable **JSON**.
- **Tiny footprint** — one dependency (`requests`); pure logic is fully unit-tested offline.

## 📦 Installation

```bash
# Clone the monorepo and enter this tool's folder
git clone https://github.com/nalmahmoud77-boop/SecurityProjects.git
cd SecurityProjects/dir-buster

# (recommended) create a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install
pip install -e .
```

That installs a `dir-buster` command. You can also run it without installing:

```bash
pip install -r requirements.txt
python -m dir_buster.cli https://example.com
```

## 🚀 Usage

```bash
# Basic scan with the built-in wordlist
dir-buster https://example.com

# Use your own wordlist (e.g. from SecLists) and append extensions
dir-buster https://example.com -w wordlist.txt -x php,html,txt

# Recurse into discovered directories, up to depth 3
dir-buster https://example.com -r --max-depth 3

# Only show 200 and 301; hide 404 and 403
dir-buster https://example.com -mc 200,301

# Hide a specific soft-404 size and rate-limit to be gentle
dir-buster https://example.com -fs 1024 --delay 0.1

# JSON output for tooling
dir-buster https://example.com --format json --output findings.json
```

### Options

| Flag | Description |
|------|-------------|
| `-w, --wordlist FILE` | Wordlist path (built-in list if omitted) |
| `-x, --extensions LIST` | Extensions to append, e.g. `php,html` (or `common`) |
| `-t, --threads N` | Concurrent requests (default: `30`) |
| `--timeout N` | Per-request timeout in seconds (default: `8`) |
| `--delay N` | Per-request delay for rate limiting (default: `0`) |
| `-r, --recursive` | Recurse into discovered directories |
| `--max-depth N` | Max recursion depth (default: `2`) |
| `-mc, --match-codes LIST` | Only show these status codes |
| `-fc, --filter-codes LIST` | Hide these status codes (default: `404`) |
| `-fs, --filter-sizes LIST` | Hide responses of these exact byte sizes |
| `-f, --format {terminal,json}` | Output format (default: `terminal`) |
| `-o, --output FILE` | Write the report to a file |
| `--no-color` | Disable ANSI colors |
| `--insecure` | Skip TLS verification |
| `--version` | Print version and exit |

Progress messages go to **stderr**, so `--format json` stays clean when redirected.

## 🧠 How soft-404 calibration works

Many servers return `200 OK` (or a fixed error page) for paths that don't exist, which makes a plain brute-forcer report everything. Before scanning a directory, dir-buster requests a few **random** paths that are guaranteed not to exist and records their `(status, size)`. Any real result matching that fingerprint (within a small tolerance) is treated as a false positive and dropped.

## 🧪 Development & tests

```bash
pip install -e ".[dev]"
pytest -v
```

The suite is **fully offline** — candidate generation, filtering, and soft-404 matching are pure functions tested with synthetic data. See [CONTRIBUTING.md](CONTRIBUTING.md).

## 🗺️ Roadmap

- [ ] Filter by word / line count (not just size)
- [ ] Content-similarity soft-404 detection (not just size)
- [ ] Custom headers, cookies, and basic auth
- [ ] CSV / HTML output
- [ ] Progress bar with live request rate

## ⚖️ Legal & ethical use

> `dir-buster` sends **many** requests to the target and is trivially logged. It is an active tool.

**Only run it against servers you own or have explicit written authorization to test.** Unauthorized brute-forcing may be illegal under computer-misuse laws and will likely violate acceptable-use policies. You are solely responsible for how you use this tool. It is provided for **authorized security testing and educational purposes only**, with no warranty (see [LICENSE](LICENSE)).

## 📄 License

Released under the [MIT License](LICENSE).
