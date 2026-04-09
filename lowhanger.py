#!/usr/bin/env python3
"""
lowhanger.py — Low-hanging fruit pentesting scanner

Scan modes:
  default (crawl)   : Crawl the target with katana/BFS, filter to HTML pages,
                      run all checks against every discovered page.
  --no-crawl        : Skip crawling — check root URL only. Fast surface scan.

Templates:
  ssl-check              Deprecated TLS 1.0 / 1.1
  http-redirect          HTTP→HTTPS enforcement + HSTS quality
  version-disclosure     Version/tech leakage in headers and error pages
  security-headers       Missing HSTS / X-Frame / X-Content-Type / CSP
  clickjacking           X-Frame-Options + CSP frame-ancestors analysis
  cors                   CORS misconfiguration (wildcard, reflected origin, null)
  host-header-redirect   Open redirect via Host header injection (12 techniques)
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
        epilog=(
            "Scan modes:\n"
            "  default      : crawl entire app, check every HTML page\n"
            "  --no-crawl   : root URL only, fast surface check\n\n"
            "Templates: " + ", ".join(ALL_TEMPLATES)
        ),
    )

    tg = p.add_argument_group("Targets")
    tg.add_argument("-t", "--target", dest="targets", metavar="URL",
                    action="append", default=[],
                    help="Target URL or domain (repeatable)")
    tg.add_argument("-l", "--list", dest="lists", metavar="FILE",
                    action="append", default=[],
                    help="File with one target per line (repeatable)")

    mg = p.add_argument_group("Mode")
    mode_ex = mg.add_mutually_exclusive_group()
    mode_ex.add_argument("--no-crawl", dest="no_crawl", action="store_true", default=False,
                         help=(
                             "Surface scan — skip crawling, check root URL only.\n"
                             "Fast but may miss headers/issues on deeper pages."
                         ))
    mode_ex.add_argument("--crawl", dest="no_crawl", action="store_false",
                         help="Full crawl mode (default)")

    sg = p.add_argument_group("Scan")
    sg.add_argument("--templates", dest="templates", metavar="ID",
                    nargs="+", default=["all"],
                    help="Template IDs (default: all)\nAvailable: {}".format(
                        " ".join(ALL_TEMPLATES)))
    sg.add_argument("--canary", dest="canary", metavar="DOMAIN", default=None,
                    help="Override canary for host-header module\n"
                         "(use Burp Collaborator / interactsh for OOB)")
    sg.add_argument("--crawl-depth", dest="crawl_depth", type=int, default=None,
                    help="Crawl depth (default: 3, ignored with --no-crawl)")
    sg.add_argument("--timeout", dest="timeout", type=int, default=10,
                    help="Per-request timeout in seconds (default: 10)")
    sg.add_argument("--proxy", dest="proxy", metavar="URL", default=None,
                    help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    sg.add_argument("--follow-redirects", dest="follow_redirects",
                    action="store_true", default=False)

    og = p.add_argument_group("Output")
    og.add_argument("-o", "--output", dest="output", metavar="FILE", default=None)
    og.add_argument("--format", dest="fmt",
                    choices=["pretty", "plain", "json"], default="pretty")
    og.add_argument("-v", "--verbose", action="store_true", default=False)

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

    mode = "no-crawl (surface)" if args.no_crawl else "crawl"
    reporter.info("Loaded {} target(s) — mode: {}".format(len(targets), mode))

    proxies = {}
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}
        reporter.info("Proxy: {}".format(args.proxy))

    engine = Engine(
        reporter         = reporter,
        template_filter  = args.templates,
        crawl_mode       = not args.no_crawl,
        crawl_depth      = args.crawl_depth,
        timeout          = args.timeout,
        follow_redirects = args.follow_redirects,
        proxies          = proxies,
    )

    # Apply canary override
    if args.canary:
        for tmpl in engine._templates:
            if tmpl.get("id") == "host-header-redirect":
                tmpl["canary"] = args.canary
        reporter.info("Canary: {}".format(args.canary))

    engine.scan(targets)
    reporter.print_summary()


if __name__ == "__main__":
    main()