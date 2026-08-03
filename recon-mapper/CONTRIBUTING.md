# Contributing to recon-mapper

Contributions are welcome — new technology signatures, additional discovery
sources, docs, and tests.

## Getting set up

```bash
git clone https://github.com/nalmahmoud77-boop/SecurityProjects.git
cd SecurityProjects/recon-mapper
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
```

## Good first contributions

- **Add a technology signature** in `recon_mapper/fingerprint.py` (`_SIGNATURES`),
  and cover it with an offline test in `tests/test_recon.py` that feeds a
  synthetic response into `fingerprint_from()`.
- **Extend the wordlist or port list** in `recon_mapper/wordlists.py`.
- **Add a discovery source** (e.g. another passive dataset) in
  `recon_mapper/subdomains.py`, keeping the parsing logic in a pure function so
  it can be tested without the network.

## Guidelines

- Keep the network layer thin and the parsing/detection logic pure and tested.
- Prefer the standard library; the only runtime dependency is `requests`.
- Be conservative with fingerprints — avoid signatures that cause false positives.
- Never commit scan output for third-party domains.

## Reporting bugs

Open an issue with the command you ran and the (redacted) output you expected
vs. what you got.
