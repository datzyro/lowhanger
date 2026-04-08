"""
modules/security_headers.py
────────────────────────────
Module: SecurityHeadersModule
Template: templates/security-headers.yaml

Crawls all endpoints on the target and checks each one for the configured
set of security headers. Produces:
  - One finding per MISSING header (endpoint with most absences highlighted)
  - A summary finding listing the worst endpoint
"""

from modules.base    import BaseModule
from core.target     import Target
from core.http_client import HttpClient
from core.reporter   import Reporter, Finding
from core.crawler    import crawl


class SecurityHeadersModule(BaseModule):

    def run(self, target: Target, client: HttpClient, reporter: Reporter) -> None:
        header_defs    = self.template.get("headers", [])
        max_endpoints  = self.template.get("max_endpoints", 0)
        crawl_depth    = self.template.get("crawl_depth", 3)

        if not header_defs:
            reporter.warn("[security-headers] No headers configured in template.")
            return

        # ── Crawl ──────────────────────────────────────────────────── #
        reporter.info("[security-headers] Crawling {} (depth={})...".format(
            target.url, crawl_depth))

        urls = crawl(
            target,
            depth      = crawl_depth,
            timeout    = client.timeout,
            proxy      = list(client.proxies.values())[0] if client.proxies else None,
            verbose    = reporter.verbose,
        )

        if max_endpoints and len(urls) > max_endpoints:
            urls = urls[:max_endpoints]

        reporter.info("[security-headers] {} endpoint(s) to check".format(len(urls)))

        # ── Check each endpoint ────────────────────────────────────── #
        # results[url] = list of missing header defs
        results = {}

        for url in urls:
            reporter.debug("  checking {}".format(url))
            try:
                resp = client.get(url)
            except (ConnectionError, TimeoutError) as e:
                reporter.debug("  skipped ({}): {}".format(url, e))
                continue

            missing = []
            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            for hdef in header_defs:
                hname = hdef["name"].lower()
                if hname not in resp_headers_lower:
                    missing.append(hdef)

            if missing:
                results[url] = missing

        if not results:
            reporter.info("[security-headers] All endpoints have all required headers.")
            return

        # ── Emit findings ──────────────────────────────────────────── #
        # Sort by number of missing headers descending so worst offender is first
        sorted_results = sorted(results.items(), key=lambda x: len(x[1]), reverse=True)
        worst_url, worst_missing = sorted_results[0]

        # Summary finding — worst endpoint
        missing_names = ", ".join(h["name"] for h in worst_missing)
        reporter.add_finding(Finding(
            template_id  = self.id,
            name         = "{} — Worst Offender".format(self.name),
            severity     = "medium",
            target       = worst_url,
            technique    = "Security Header Audit (crawled {} endpoints)".format(len(urls)),
            evidence     = "{} header(s) missing: {}".format(len(worst_missing), missing_names),
            detail       = (
                "This endpoint is missing the most security headers out of all "
                "{} endpoints crawled. Missing: {}".format(len(urls), missing_names)
            ),
            remediation  = self.remediation,
        ))

        # Per-header findings for every affected endpoint
        # Group by header name so the report is readable
        header_to_urls = {}
        for url, missing_list in results.items():
            for hdef in missing_list:
                hname = hdef["name"]
                header_to_urls.setdefault(hname, []).append((url, hdef))

        for hname, url_list in sorted(header_to_urls.items(),
                                       key=lambda x: len(x[1]), reverse=True):
            hdef     = url_list[0][1]
            severity = hdef.get("severity", "low")
            required = hdef.get("required", True)

            if not required:
                severity = "info"

            affected_urls = [u for u, _ in url_list]
            sample        = affected_urls[:5]
            extra         = len(affected_urls) - len(sample)
            sample_str    = "\n    ".join(sample)
            if extra:
                sample_str += "\n    ... and {} more".format(extra)

            reporter.add_finding(Finding(
                template_id  = self.id,
                name         = "{} — {} Missing".format(self.name, hname),
                severity     = severity,
                target       = target.url,
                technique    = "Security Header Audit",
                evidence     = "{} / {} endpoint(s) missing {}\n    {}".format(
                    len(affected_urls), len(urls), hname, sample_str),
                detail       = hdef.get("note", ""),
                remediation  = self.remediation,
            ))

        reporter.info("[security-headers] Done. {} endpoint(s) had missing headers.".format(
            len(results)))
