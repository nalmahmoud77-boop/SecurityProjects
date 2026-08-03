# 🔐 Security Projects

[![CI](https://github.com/nalmahmoud77-boop/SecurityProjects/actions/workflows/ci.yml/badge.svg)](https://github.com/nalmahmoud77-boop/SecurityProjects/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A collection of small, focused tools for **web-application security testing**. Each tool lives in its own subfolder with its own README, tests, and usage examples. The goal is depth over breadth — each does one job well and explains the *why* behind every finding.

## 📦 Projects

| Tool | What it does | Status |
|------|--------------|--------|
| [**header-analyzer**](header-analyzer/) | Audits a site's HTTP security headers (CSP, HSTS, cookies, …), grades it A–F, and gives copy-paste remediation. | ✅ Available |
| [**recon-mapper**](recon-mapper/) | Subdomain enumeration (passive + active), live-host resolution, web-stack fingerprinting, and optional port scanning. | ✅ Available |
| [**dir-buster**](dir-buster/) | Fast content & endpoint discovery with recursion and soft-404 false-positive filtering. | ✅ Available |
| vuln-scanner | Focused scanner for reflected XSS, SQLi, and open redirects. | 🚧 Planned |
| vuln-lab | Deliberately vulnerable app + exploit scripts for safe practice. | 🚧 Planned |

> More tools are added over time. Each one is self-contained — jump into its folder to get started.

## 🚀 Quick start

```bash
git clone https://github.com/nalmahmoud77-boop/SecurityProjects.git
cd SecurityProjects/header-analyzer
pip install -e .
header-analyzer example.com
```

See each tool's own README for full usage.

## ⚖️ Legal & ethical use

These tools are for **authorized security testing and educational use only.** Only test systems you own or have explicit written permission to assess. Unauthorized scanning or testing may be illegal and violate terms of service. You are solely responsible for how you use this software, which is provided without warranty (see [LICENSE](LICENSE)).

## 📄 License

All projects in this repository are released under the [MIT License](LICENSE).
