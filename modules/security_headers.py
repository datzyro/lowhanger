"""
modules/security_headers.py
Module: SecurityHeadersModule

Single finding only — the endpoint with the most missing headers.
Cause block shows each header in red (missing) or green (present).
Affected block lists every endpoint that had at least one header missing.
"""

from colorama import Fore, Style
from modules.base     import BaseModule
from core.target      import Target
from core.http_client import HttpClient
from core.reporter    import Reporter, Finding


class SecurityHeadersModule(BaseModule):

    def run(self, target: Target, client: HttpClient,
            reporter: Reporter, urls: list = None) -> None:

        header_defs = self.template.get("headers", [])
        if not header_defs:
            reporter.warn("[security-headers] No headers configured in template.")
            return

        if not urls:
            reporter.info("[security-headers] No URLs to check.")
            return

        reporter.info("[security-headers] Checking {} page(s) for {} header(s)".format(
            len(urls), len(header_defs)))

        # results[url] = {header_name: True (present) / False (missing)}
        results = {}

        for url in urls:
            reporter.debug("  {}".format(url))
            try:
                resp = client.get(url)
            except (ConnectionError, TimeoutError) as e:
                reporter.debug("  skipped {}: {}".format(url, e))
                continue

            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            url_result = {
                hdef["name"]: hdef["name"].lower() in resp_headers_lower
                for hdef in header_defs
            }
            # Only store URLs that have at least one missing header
            if not all(url_result.values()):
                results[url] = url_result

        if not results:
            reporter.info("[security-headers] All pages have all required headers.")
            return

        # Pick the worst offender — most missing headers
        worst_url = max(results, key=lambda u: sum(1 for v in results[u].values() if not v))
        worst_result = results[worst_url]
        missing_count = sum(1 for v in worst_result.values() if not v)

        # Build the colored cause block
        # Each header line: green tick if present, red cross if missing
        cause_lines = []
        for hname, present in worst_result.items():
            if present:
                cause_lines.append(
                    "  {}✓  {}{}".format(Fore.GREEN, hname, Style.RESET_ALL))
            else:
                cause_lines.append(
                    "  {}✗  {}{}".format(Fore.RED, hname, Style.RESET_ALL))

        # All affected endpoints (any missing header) sorted by missing count desc
        affected_sorted = sorted(
            results.items(),
            key=lambda x: sum(1 for v in x[1].values() if not v),
            reverse=True,
        )

        affected_lines = []
        for url, url_result in affected_sorted:
            missing_here = [h for h, present in url_result.items() if not present]
            affected_lines.append("  {}  [missing: {}]".format(
                url, ", ".join(missing_here)))

        cause = "\n".join(cause_lines)
        affected_block = "\n".join(affected_lines)

        reporter.add_finding(Finding(
            template_id = self.id,
            name        = "Missing Security Headers",
            severity    = "medium",
            target      = target.url,
            affected    = affected_block,
            technique   = "Security header audit ({} pages checked)".format(len(urls)),
            cause       = cause,
        ))

        reporter.info("[security-headers] Done. {} page(s) with missing headers.".format(
            len(results)))