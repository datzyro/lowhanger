"""
modules/security_headers.py
Module: SecurityHeadersModule
"""

from modules.base     import BaseModule
from core.target      import Target
from core.http_client import HttpClient
from core.reporter    import Reporter, Finding
from core.crawler     import crawl


class SecurityHeadersModule(BaseModule):

    def run(self, target: Target, client: HttpClient, reporter: Reporter) -> None:
        header_defs   = self.template.get("headers", [])
        max_endpoints = self.template.get("max_endpoints", 0)
        crawl_depth   = self.template.get("crawl_depth", 3)

        if not header_defs:
            reporter.warn("[security-headers] No headers configured in template.")
            return

        reporter.info("[security-headers] Crawling {} (depth={})...".format(
            target.url, crawl_depth))

        urls = crawl(
            target,
            depth   = crawl_depth,
            timeout = client.timeout,
            proxy   = list(client.proxies.values())[0] if client.proxies else None,
            verbose = reporter.verbose,
        )

        if max_endpoints and len(urls) > max_endpoints:
            urls = urls[:max_endpoints]

        reporter.info("[security-headers] {} endpoint(s) to check".format(len(urls)))

        # results[url] = list of missing header names
        results = {}

        for url in urls:
            reporter.debug("  checking {}".format(url))
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
            reporter.info("[security-headers] All endpoints have all required headers.")
            return

        sorted_results = sorted(results.items(), key=lambda x: len(x[1]), reverse=True)
        worst_url, worst_missing = sorted_results[0]

        # Worst offender — one summary finding
        reporter.add_finding(Finding(
            template_id = self.id,
            name        = "Missing Security Headers — Worst Offender",
            severity    = "medium",
            target      = target.url,
            affected    = worst_url,
            technique   = "Security header audit ({} endpoints crawled)".format(len(urls)),
            cause       = "Missing {}/{} required headers: {}".format(
                len(worst_missing), len(header_defs),
                ", ".join(worst_missing)),
        ))

        # Per-header findings — group by header name, one finding per missing header
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
                              else "{} endpoints".format(len(affected_urls)),
                technique   = "Security header audit",
                cause       = "{} header absent on {} endpoint(s):\n              {}".format(
                    hname, len(affected_urls), url_block),
            ))

        reporter.info("[security-headers] Done. {} endpoint(s) with missing headers.".format(
            len(results)))