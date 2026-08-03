"""Command-line entry point for dir-buster."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional, Set

from . import __version__
from .core import Filter
from .report import to_json, to_terminal
from .scanner import run_scan
from .wordlists import COMMON_EXTENSIONS, DEFAULT_PATHS


def _parse_codes(value: Optional[str]) -> Optional[Set[int]]:
    if not value:
        return None
    codes: Set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if part:
            codes.add(int(part))
    return codes


def _parse_ints(value: Optional[str]) -> Set[int]:
    return _parse_codes(value) or set()


def _load_wordlist(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        return [line.rstrip("\n") for line in handle]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dir-buster",
        description="Discover hidden directories and files on a web server by "
        "brute-forcing paths from a wordlist, with soft-404 calibration.",
        epilog="AUTHORIZED USE ONLY. Brute-forcing paths sends many requests "
        "and is easily logged. Only run against targets you own or are "
        "explicitly permitted to test.",
    )
    parser.add_argument("url", help="Target base URL, e.g. https://example.com")
    parser.add_argument(
        "-w", "--wordlist",
        help="Path to a wordlist (one path per line). Uses a built-in list if omitted.",
    )
    parser.add_argument(
        "-x", "--extensions",
        help="Comma-separated extensions to append, e.g. php,html,txt. "
        "Pass 'common' to use a built-in set.",
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=30,
        help="Number of concurrent requests (default 30).",
    )
    parser.add_argument(
        "--timeout", type=float, default=8.0,
        help="Per-request timeout in seconds (default 8).",
    )
    parser.add_argument(
        "--delay", type=float, default=0.0,
        help="Delay in seconds added per request, per thread (rate limiting).",
    )
    parser.add_argument(
        "-r", "--recursive", action="store_true",
        help="Recurse into discovered directories.",
    )
    parser.add_argument(
        "--max-depth", type=int, default=2,
        help="Maximum recursion depth (default 2).",
    )
    parser.add_argument(
        "-mc", "--match-codes",
        help="Only show these status codes, e.g. 200,301,403 (default: show all but filtered).",
    )
    parser.add_argument(
        "-fc", "--filter-codes", default="404",
        help="Hide these status codes (default: 404).",
    )
    parser.add_argument(
        "-fs", "--filter-sizes",
        help="Hide responses of these exact byte sizes, e.g. 0,1234.",
    )
    parser.add_argument(
        "-f", "--format", choices=["terminal", "json"], default="terminal",
        help="Output format (default: terminal).",
    )
    parser.add_argument("-o", "--output", help="Write the report to a file.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    parser.add_argument(
        "--insecure", action="store_true", help="Do not verify TLS certificates.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    words = DEFAULT_PATHS
    if args.wordlist:
        try:
            words = _load_wordlist(args.wordlist)
        except OSError as exc:
            print(f"error: could not read wordlist: {exc}", file=sys.stderr)
            return 2

    extensions: Optional[List[str]] = None
    if args.extensions:
        if args.extensions.strip().lower() == "common":
            extensions = COMMON_EXTENSIONS
        else:
            extensions = [e for e in args.extensions.split(",") if e.strip()]

    try:
        flt = Filter(
            match_codes=_parse_codes(args.match_codes),
            filter_codes=_parse_ints(args.filter_codes),
            filter_sizes=_parse_ints(args.filter_sizes),
        )
    except ValueError:
        print("error: status codes and sizes must be integers.", file=sys.stderr)
        return 2

    def progress(msg: str) -> None:
        print(f"[*] {msg}", file=sys.stderr)

    result = run_scan(
        args.url,
        words=words,
        extensions=extensions,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        recursive=args.recursive,
        max_depth=args.max_depth,
        filter_config=flt,
        verify_tls=not args.insecure,
        progress=progress,
    )

    if args.format == "json":
        rendered = to_json(result)
    else:
        use_color = not args.no_color and (args.output is None)
        rendered = to_terminal(result, use_color=use_color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        print(
            f"Report written to {args.output}  ({len(result.findings)} findings)",
            file=sys.stderr,
        )
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
