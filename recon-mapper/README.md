# 🛰️ recon-mapper

> Map a domain's external attack surface in one command — discover subdomains, find which hosts are live, fingerprint their web stack, and optionally scan common ports.

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/nalmahmoud77-boop/SecurityProjects/actions/workflows/ci.yml/badge.svg)](https://github.com/nalmahmoud77-boop/SecurityProjects/actions/workflows/ci.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-orange.svg)](CONTRIBUTING.md)

`recon-mapper` is a focused reconnaissance tool for the **discovery phase** of a web-app assessment. Point it at a domain and it combines passive and active techniques into a single, readable map of the attack surface.

```
  Recon Report
  Domain: example.com
  Surface: 7 subdomain(s) discovered, 4 live
  ------------------------------------------------------------
  ● example.com
      ip:   93.184.216.34
      http: 200 Example Domain
      server: ECS (dcb/7F watts)
  ● api.example.com
      ip:   93.184.216.40
      http: 200
      tech: Nginx, PHP
      ports: 80/http, 443/https
  ○ old.example.com  (no DNS)
```

---

## ✨ Features

- **Passive subdomain discovery** — queries [crt.sh](https://crt.sh) Certificate Transparency logs to find real, previously-issued subdomains **without sending a packet to the target**.
- **Active subdomain discovery** — concurrent DNS brute-forcing with a built-in wordlist (or bring your own with `--wordlist`).
- **Live-host resolution** — resolves every candidate and reports which ones actually exist.
- **Web fingerprinting** — probes live hosts over HTTPS/HTTP and identifies the server, `X-Powered-By`, page title, and technologies (WordPress, Django, Laravel, React, Nginx, Cloudflare, and more) from headers, cookies, and body.
- **Optional port scanning** — a fast concurrent TCP-connect scan of common ports, gated behind an explicit `--ports` flag.
- **Clean output** — colored terminal report or machine-readable **JSON** for piping into other tools.
- **Tiny footprint** — one dependency (`requests`); everything else is the standard library. Fully unit-tested offline.

## 📦 Installation

```bash
# Clone the monorepo and enter this tool's folder
git clone https://github.com/nalmahmoud77-boop/SecurityProjects.git
cd SecurityProjects/recon-mapper

# (recommended) create a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install
pip install -e .
```

That installs a `recon-mapper` command. You can also run it without installing:

```bash
pip install -r requirements.txt
python -m recon_mapper.cli example.com
```

## 🚀 Usage

```bash
# Full recon (passive + active subdomains, resolve, fingerprint)
recon-mapper example.com

# Passive only — no DNS brute-forcing, only certificate transparency
recon-mapper example.com --passive-only

# Use a bigger wordlist (e.g. from SecLists)
recon-mapper example.com --wordlist subdomains-top1million.txt

# Also scan the top 20 common ports on live hosts
recon-mapper example.com --ports

# JSON output for tooling / reports
recon-mapper example.com --format json --output recon.json
```

### Options

| Flag | Description |
|------|-------------|
| `--passive-only` | Skip DNS brute-forcing; use crt.sh only |
| `-w, --wordlist FILE` | Custom subdomain wordlist (one name per line) |
| `--ports` | Enable a TCP port scan of live hosts |
| `--top-ports N` | Number of common ports to scan (default: `20`) |
| `--threads N` | Concurrency for DNS/HTTP work (default: `40`) |
| `--timeout N` | Per-lookup timeout in seconds (default: `3`) |
| `-f, --format {terminal,json}` | Output format (default: `terminal`) |
| `-o, --output FILE` | Write the report to a file |
| `--no-color` | Disable ANSI colors |
| `--insecure` | Skip TLS verification when fingerprinting |
| `--version` | Print version and exit |

Progress messages are printed to **stderr**, so `--format json` piped to a file or `jq` stays clean.

## 🧠 How it works

1. **Enumerate** — merge subdomains from crt.sh (passive) and DNS brute-force (active).
2. **Resolve** — concurrently resolve every candidate; keep the ones with DNS records.
3. **Fingerprint** — request each live host and detect stack details from the response.
4. **Scan** *(optional)* — TCP-connect scan the common ports on each live host.

## 🧪 Development & tests

```bash
pip install -e ".[dev]"
pytest -v
```

The suite is **fully offline** — parsing and fingerprint detection are pure functions fed synthetic data, so no network access is needed. See [CONTRIBUTING.md](CONTRIBUTING.md) to add a technology signature.

## 🗺️ Roadmap

- [ ] More passive sources (e.g. additional CT datasets)
- [ ] Wildcard-DNS detection to filter brute-force false positives
- [ ] CSV / HTML report formats
- [ ] Optional screenshot capture of live hosts
- [ ] Resume / cache of previous runs

## ⚖️ Legal & ethical use

> `recon-mapper` performs **active** operations — DNS brute-forcing and (optionally) port scanning — against the domain you specify.

**Only run it against domains you own or have explicit written authorization to test.** Unauthorized scanning may be illegal under computer-misuse laws and violate acceptable-use policies. Passive discovery via crt.sh queries a third-party public service. You are solely responsible for how you use this tool. It is provided for **authorized security testing and educational purposes only**, with no warranty (see [LICENSE](LICENSE)).

## 📄 License

Released under the [MIT License](LICENSE).
