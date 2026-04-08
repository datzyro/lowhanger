#!/usr/bin/env python3
"""
lowhanger.py — Low-hanging fruit pentesting scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Templates available:
  ssl-check              Deprecated TLS versions (wraps testssl.sh)
  http-redirect          HTTP→HTTPS enforcement + HSTS quality
  security-headers       Missing security headers across all crawled endpoints
  clickjacking           X-Frame-Options + CSP frame-ancestors analysis
  host-header-redirect   Open redirect via Host header injection (12 techniques)

External tools used (optional — graceful fallback if absent):
  katana       Endpoint crawler   https://github.com/projectdiscovery/katana
  testssl.sh   TLS scanner        https://testssl.sh

Usage:
  python lowhanger.py -t https://example.com
  python lowhanger.py -t https://example.com --templates security-headers clickjacking
  python lowhanger.py -l targets.txt --templates all -o results.json --format json
  python lowhanger.py -t https://example.com --proxy http://127.0.0.1:8080
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from core.target   import load_targets
from core.engine   import Engine
from core.reporter import Reporter

ALL_TEMPLATES = [
    "ssl-check",
    "http-redirect",
    "version-disclosure",
    "security-headers",
    "clickjacking",
    "cors",
    "host-header-redirect",
]


def parse_args():
    p = argparse.ArgumentParser(
        prog="lowhanger",
        description="Low-hanging fruit pentesting scanner — template-based.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="\n".join([
            "Templates: " + ", ".join(ALL_TEMPLATES),
            "",
            "External tools (optional):",
            "  katana      : endpoint crawler (github.com/projectdiscovery/katana)",
            "  testssl.sh  : TLS scanner      (testssl.sh)",
        ]),
    )

    tg = p.add_argument_group("Targets")
    tg.add_argument("-t", "--target", dest="targets", metavar="URL",
                    action="append", default=[],
                    help="Target URL or domain (repeatable)")
    tg.add_argument("-l", "--list", dest="lists", metavar="FILE",
                    action="append", default=[],
                    help="File with one target per line (repeatable)")

    sg = p.add_argument_group("Scan")
    sg.add_argument("--templates", dest="templates", metavar="ID",
                    nargs="+", default=["all"],
                    help="Template IDs to run (default: all)\n"
                         "Available: {}".format(" ".join(ALL_TEMPLATES)))
    sg.add_argument("--canary", dest="canary", metavar="DOMAIN", default=None,
                    help="Override canary domain for host-header module\n"
                         "(use Burp Collaborator / interactsh for OOB detection)")
    sg.add_argument("--crawl-depth", dest="crawl_depth", type=int, default=None,
                    help="Override crawl depth for all templates (default: per-template)")
    sg.add_argument("--timeout", dest="timeout", type=int, default=10,
                    help="Per-request timeout in seconds (default: 10)")
    sg.add_argument("--proxy", dest="proxy", metavar="URL", default=None,
                    help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    sg.add_argument("--follow-redirects", dest="follow_redirects",
                    action="store_true", default=False,
                    help="Follow redirects (most checks need raw 3xx — use carefully)")

    og = p.add_argument_group("Output")
    og.add_argument("-o", "--output", dest="output", metavar="FILE", default=None,
                    help="Write results to file")
    og.add_argument("--format", dest="fmt",
                    choices=["pretty", "plain", "json"], default="pretty",
                    help="Output format (default: pretty)")
    og.add_argument("-v", "--verbose", action="store_true", default=False,
                    help="Verbose output")

    return p.parse_args()


def main():
    args = parse_args()

    reporter = Reporter(
        verbose=args.verbose,
        output_file=args.output,
        fmt=args.fmt,
    )
    reporter.print_banner()

    if not args.targets and not args.lists:
        reporter.error("No targets specified. Use -t <url> or -l <file>.")
        sys.exit(1)

    try:
        targets = load_targets(paths=args.lists, urls=args.targets)
    except FileNotFoundError as e:
        reporter.error(str(e))
        sys.exit(1)

    if not targets:
        reporter.error("Target list is empty.")
        sys.exit(1)

    reporter.info("Loaded {} unique target(s)".format(len(targets)))

    proxies = {}
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}
        reporter.info("Routing through proxy: {}".format(args.proxy))

    engine = Engine(
        reporter=reporter,
        template_filter=args.templates,
        timeout=args.timeout,
        follow_redirects=args.follow_redirects,
        proxies=proxies,
    )

    # Apply overrides to loaded templates
    for tmpl in engine._templates:
        if args.canary and tmpl.get("id") == "host-header-redirect":
            tmpl["canary"] = args.canary
        if args.crawl_depth is not None and "crawl_depth" in tmpl:
            tmpl["crawl_depth"] = args.crawl_depth

    if args.canary:
        reporter.info("Canary override: {}".format(args.canary))

    engine.scan(targets)
    reporter.print_summary()


if __name__ == "__main__":
    main()
