"""
modules/security_headers.py
Module: SecurityHeadersModule

Receives a pre-crawled, HTML-filtered URL list from the engine.
No internal crawling.
"""

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

        # results[url] = list of missing header names
        results = {}

        for url in urls:
            reporter.debug("  {}".format(url))
            try:
                resp = client.get(url)
            except (ConnectionError, TimeoutError) as e:
                reporter.debug("  skipped {}: {}".format(url, e))
                continue

            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            missing = [
                hdef["name"] for hdef in header_defs
                if hdef["name"].lower() not in resp_headers_lower
            ]
            if missing:
                results[url] = missing

        if not results:
            reporter.info("[security-headers] All pages have required headers.")
            return

        sorted_results = sorted(results.items(), key=lambda x: len(x[1]), reverse=True)
        worst_url, worst_missing = sorted_results[0]

        # Worst offender summary
        reporter.add_finding(Finding(
            template_id = self.id,
            name        = "Missing Security Headers — Worst Offender",
            severity    = "medium",
            target      = target.url,
            affected    = worst_url,
            technique   = "Security header audit ({} pages checked)".format(len(urls)),
            cause       = "Missing {}/{} required headers: {}".format(
                len(worst_missing), len(header_defs), ", ".join(worst_missing)),
        ))

        # Per-header breakdown
        header_to_urls = {}
        for url, missing_list in results.items():
            for hname in missing_list:
                header_to_urls.setdefault(hname, []).append(url)

        for hname, affected_urls in sorted(
                header_to_urls.items(), key=lambda x: -len(x[1])):

            hdef     = next((h for h in header_defs if h["name"] == hname), {})
            severity = hdef.get("severity", "medium")

            sample    = affected_urls[:5]
            extra     = len(affected_urls) - len(sample)
            url_block = "\n              ".join(sample)
            if extra:
                url_block += "\n              ... and {} more".format(extra)

            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "Missing Security Header — {}".format(hname),
                severity    = severity,
                target      = target.url,
                affected    = affected_urls[0] if len(affected_urls) == 1
                              else "{} pages".format(len(affected_urls)),
                technique   = "Security header audit",
                cause       = "{} absent on {} page(s):\n              {}".format(
                    hname, len(affected_urls), url_block),
            ))

        reporter.info("[security-headers] Done. {} page(s) with missing headers.".format(
            len(results)))