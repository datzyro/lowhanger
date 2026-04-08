"""
modules/version_disclosure.py
──────────────────────────────
Module: VersionDisclosureModule
Template: templates/version-disclosure.yaml

Three detection vectors:
  1. Headers     — checks every crawled endpoint for disclosure headers
  2. Error pages — deliberately triggers 404/403/500 to surface server banners
  3. Body regex  — scans response bodies for known version string patterns

De-duplication:
  Each unique (technology, version, location) tuple is reported once,
  regardless of how many endpoints expose it. The finding records ALL
  affected URLs so the report stays readable.
"""

import re
from collections import defaultdict
from modules.base     import BaseModule
from core.target      import Target
from core.http_client import HttpClient
from core.reporter    import Reporter, Finding
from core.crawler     import crawl


class VersionDisclosureModule(BaseModule):

    def run(self, target: Target, client: HttpClient, reporter: Reporter) -> None:
        crawl_depth       = self.template.get("crawl_depth", 2)
        disclosure_headers= self.template.get("disclosure_headers", [])
        error_paths       = self.template.get("error_paths", [])
        body_patterns_cfg = self.template.get("body_patterns", [])

        # Compile body regex patterns once
        compiled_patterns = []
        for bp in body_patterns_cfg:
            try:
                compiled_patterns.append({
                    "re":         re.compile(bp["pattern"], re.IGNORECASE),
                    "technology": bp.get("technology", "Unknown"),
                    "severity":   bp.get("severity", "low"),
                    "raw":        bp["pattern"],
                })
            except re.error as e:
                reporter.warn("[version-disclosure] Bad pattern '{}': {}".format(
                    bp.get("pattern"), e))

        # ── Crawl ──────────────────────────────────────────────────── #
        reporter.info("[version-disclosure] Crawling {} (depth={})...".format(
            target.url, crawl_depth))

        urls = crawl(
            target,
            depth   = crawl_depth,
            timeout = client.timeout,
            proxy   = list(client.proxies.values())[0] if client.proxies else None,
            verbose = reporter.verbose,
        )

        # Append error-probe URLs (relative to target origin)
        error_urls = []
        for path in error_paths:
            error_urls.append(target.origin + path)

        all_urls = list(dict.fromkeys(urls + error_urls))   # preserve order, dedupe
        reporter.info("[version-disclosure] {} endpoint(s) + {} error probe(s) to check".format(
            len(urls), len(error_urls)))

        # ──────────────────────────────────────────────────────────── #
        # Collect raw hits: keyed by (vector, technology/header, value)
        # value → list of (url, context)
        # ──────────────────────────────────────────────────────────── #
        # header hits:   key = ("header", header_name, header_value)
        # body hits:     key = ("body",   technology,  version_string)
        hits = defaultdict(list)   # key → [(url, context_snippet)]

        for url in all_urls:
            is_error_probe = url in error_urls
            reporter.debug("  {} {}".format(
                "[error-probe]" if is_error_probe else "[crawled]", url))

            try:
                resp = client.get(url)
            except (ConnectionError, TimeoutError) as e:
                reporter.debug("  skipped {}: {}".format(url, e))
                continue

            # ── Vector 1 & 2: Headers (same logic for normal + error pages) ── #
            for hname in disclosure_headers:
                hval = resp.headers.get(hname) or resp.headers.get(hname.lower())
                if hval:
                    key = ("header", hname, hval.strip())
                    hits[key].append((url, "Header: {}: {}".format(hname, hval.strip())))

            # ── Vector 3: Body patterns ── #
            if resp.text:
                for pat in compiled_patterns:
                    for m in pat["re"].finditer(resp.text):
                        # Grab the version portion (last non-empty group, or full match)
                        version = next(
                            (g for g in reversed(m.groups()) if g), m.group(0))
                        snippet = resp.text[max(0, m.start()-30):m.end()+30].strip()
                        snippet = " ".join(snippet.split())   # collapse whitespace
                        key = ("body", pat["technology"], version)
                        hits[key].append((url, snippet))

        if not hits:
            reporter.info("[version-disclosure] No version/technology disclosure found.")
            return

        # ── Emit one finding per unique (vector, tech, value) ─────── #
        for key, occurrences in sorted(hits.items(), key=lambda x: -len(x[1])):
            vector, label, value = key
            urls_affected = list(dict.fromkeys(u for u, _ in occurrences))
            sample        = urls_affected[:5]
            extra         = len(urls_affected) - len(sample)
            url_list      = "\n    ".join(sample)
            if extra:
                url_list += "\n    ... and {} more".format(extra)

            # Pick severity
            if vector == "header":
                # Server header disclosing a version string = low
                # X-Powered-By = low, X-AspNet = info
                sev = _header_severity(label, value)
                technique = "Response header disclosure"
                evidence  = "{}: {}".format(label, value)
                detail    = (
                    "The '{}' response header discloses '{}' on {} endpoint(s).\n    {}".format(
                        label, value, len(urls_affected), url_list)
                )
            else:
                # Body pattern — use per-pattern severity from template
                pat_match = next(
                    (p for p in compiled_patterns if p["technology"] == label), None)
                sev       = pat_match["severity"] if pat_match else "low"
                technique = "Response body pattern match ({})".format(label)
                evidence  = "{} version string detected: {}".format(label, value)
                detail    = (
                    "Version string for {} ('{}') found in response body on "
                    "{} endpoint(s).\n    {}".format(
                        label, value, len(urls_affected), url_list)
                )
                # Provide context snippet from first occurrence
                if occurrences[0][1]:
                    detail += "\n    Context: ...{}...".format(occurrences[0][1])

            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "{} — {} ({})".format(
                    self.name, label, vector),
                severity    = sev,
                target      = target.url,
                technique   = technique,
                evidence    = evidence,
                detail      = detail,
                remediation = self.remediation,
            ))

        reporter.info("[version-disclosure] Done. {} unique disclosure(s) found.".format(
            len(hits)))


def _header_severity(header_name: str, value: str) -> str:
    """
    Assign severity based on header name and whether the value contains
    a version number (version = worse than just a product name).
    """
    has_version = bool(re.search(r'\d+\.\d+', value))
    name_lower  = header_name.lower()

    if name_lower == "server":
        return "low" if has_version else "info"
    if name_lower in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        return "low"
    if name_lower in ("via", "x-generator"):
        return "info"
    return "info"
