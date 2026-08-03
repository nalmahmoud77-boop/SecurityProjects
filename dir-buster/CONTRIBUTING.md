# Contributing to dir-buster

Contributions are welcome — wordlist additions, new filters, output formats,
docs, and tests.

## Getting set up

```bash
git clone https://github.com/nalmahmoud77-boop/SecurityProjects.git
cd SecurityProjects/dir-buster
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
```

## Architecture

The code separates **pure logic** from the **network layer** so most behavior
is testable offline:

- `core.py` — candidate generation, URL helpers, filtering, soft-404 matching,
  and the data models. All deterministic and unit-tested.
- `scanner.py` — the request engine: probing, calibration, the concurrent scan
  loop, and recursion.
- `report.py` / `cli.py` — output and argument parsing.

## Good first contributions

- Add a new **filter** (e.g. filter by word or line count) in `core.py:Filter`
  and cover it with a test.
- Improve **soft-404 calibration** (e.g. content-similarity instead of size).
- Add an output format (CSV, HTML).

## Guidelines

- Keep new logic in pure functions where possible and add an offline test.
- The only runtime dependency is `requests`.
- Never commit scan output for third-party targets.
