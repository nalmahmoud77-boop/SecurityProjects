# Contributing to Header Analyzer

Thanks for your interest in improving Header Analyzer! Contributions of all
sizes are welcome — bug reports, new header checks, docs, and tests.

## Getting set up

```bash
git clone https://github.com/nalmahmoud77-boop/SecurityProjects.git
cd SecurityProjects/header-analyzer
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
```

## Adding a new header check

The architecture is designed to make this easy:

1. Open `header_analyzer/checks.py`.
2. Write a function `check_<name>(headers: dict) -> Finding`. Use the `_get()`
   helper for case-insensitive lookups and return a `Finding` with an
   appropriate `severity`, `detail`, and `remediation`.
3. Register the function in the `ALL_CHECKS` list.
4. Add a unit test in `tests/test_checks.py` that feeds a synthetic header
   dict and asserts on the result (no network needed).

## Guidelines

- Keep checks **accurate over noisy** — a false positive erodes trust in the tool.
- Every failing finding should include a concrete `remediation` value.
- Run `pytest` before opening a PR; add tests for new behavior.
- Keep the dependency footprint minimal (currently just `requests`).

## Reporting bugs

Open an issue with the target behavior, the command you ran, and the output you
expected vs. what you got. Never include credentials or sensitive URLs.
