"""Command-line entry point for recon-mapper."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .dns_utils import is_valid_hostname
from .mapper import run_recon
from .report import to_json, to_terminal


def _load_wordlist(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        return [line.strip() for line in handle if line.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon-mapper",
        description="Map a domain's attack surface: enumerate subdomains, "
        "resolve live hosts, fingerprint web stacks, and optionally scan ports.",
        epilog="AUTHORIZED USE ONLY. Only run this against domains you own or "
        "have explicit written permission to test. Port scanning and DNS "
        "brute-forcing may be logged and, without authorization, may be illegal.",
    )
    parser.add_argument("domain", help="Target apex domain, e.g. example.com")
    parser.add_argument(
        "--passive-only",
        action="store_true",
        help="Skip DNS brute-forcing; use certificate transparency only.",
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        help="Path to a custom subdomain wordlist (one name per line).",
    )
    parser.add_argument(
        "--ports",
        action="store_true",
        help="Enable a TCP port scan of live hosts (more intrusive).",
    )
    parser.add_argument(
        "--top-ports",
        type=int,
        default=20,
        metavar="N",
        help="Number of common ports to scan when --ports is set (default 20).",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=40,
        help="Concurrency for DNS/HTTP work (default 40).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Per-request DNS/connect timeout in seconds (default 3).",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["terminal", "json"],
        default="terminal",
        help="Output format (default: terminal).",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write the report to a file instead of stdout.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in terminal output.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Do not verify TLS certificates when fingerprinting.",
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

    domain = args.domain.strip().lower().lstrip("*.").rstrip(".")
    if not is_valid_hostname(domain):
        print(f"error: '{args.domain}' is not a valid domain.", file=sys.stderr)
        return 2

    wordlist = None
    if args.wordlist:
        try:
            wordlist = _load_wordlist(args.wordlist)
        except OSError as exc:
            print(f"error: could not read wordlist: {exc}", file=sys.stderr)
            return 2

    # Progress goes to stderr so it never pollutes JSON/redirected stdout.
    def progress(msg: str) -> None:
        print(f"[*] {msg}", file=sys.stderr)

    result = run_recon(
        domain,
        wordlist=wordlist,
        passive_only=args.passive_only,
        scan_ports=args.ports,
        top_ports_count=args.top_ports,
        threads=args.threads,
        timeout=args.timeout,
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
            f"Report written to {args.output}  "
            f"({len(result.live_hosts)} live of {len(result.hosts)} hosts)",
            file=sys.stderr,
        )
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
