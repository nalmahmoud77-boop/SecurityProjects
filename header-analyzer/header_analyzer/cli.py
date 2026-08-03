"""Command-line entry point for the security header analyzer."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

import requests

from . import __version__
from .analyzer import analyze
from .report import to_html, to_json, to_terminal


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="header-analyzer",
        description="Audit a website's HTTP security headers, grade the "
        "configuration A-F, and get remediation advice.",
        epilog="For authorized testing and educational use only. Only scan "
        "systems you own or have explicit permission to test.",
    )
    parser.add_argument("url", help="Target URL or hostname (https:// assumed).")
    parser.add_argument(
        "-f",
        "--format",
        choices=["terminal", "json", "html"],
        default="terminal",
        help="Output format (default: terminal).",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write the report to a file instead of stdout.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in terminal output.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Do not verify TLS certificates (use with caution).",
    )
    parser.add_argument(
        "--fail-under",
        type=int,
        metavar="SCORE",
        help="Exit with code 1 if the score is below SCORE (useful in CI).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        result = analyze(
            args.url,
            timeout=args.timeout,
            verify_tls=not args.insecure,
        )
    except requests.exceptions.SSLError:
        print(
            "error: TLS certificate verification failed. Re-run with --insecure "
            "to bypass (only if you understand the risk).",
            file=sys.stderr,
        )
        return 2
    except requests.RequestException as exc:
        print(f"error: could not reach target: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        rendered = to_json(result)
    elif args.format == "html":
        rendered = to_html(result)
    else:
        use_color = not args.no_color and (args.output is None)
        rendered = to_terminal(result, use_color=use_color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        print(f"Report written to {args.output}  (grade {result.grade}, "
              f"{result.score}/100)")
    else:
        print(rendered)

    if args.fail_under is not None and result.score < args.fail_under:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
