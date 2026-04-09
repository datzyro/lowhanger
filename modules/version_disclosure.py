"""
modules/version_disclosure.py
Module: VersionDisclosureModule

Receives a pre-crawled, HTML-filtered URL list from the engine.
Also appends error-probe URLs (404 triggers) to surface server banners.
"""

import re
from collections import defaultdict
from modules.base     import BaseModule
from core.target      import Target
from core.http_client import HttpClient
from core.reporter    import Reporter, Finding


class VersionDisclosureModule(BaseModule):

    def run(self, target: Target, client: HttpClient,
            reporter: Reporter, urls: list = None) -> None:

        disclosure_headers = self.template.get("disclosure_headers", [])
        error_paths        = self.template.get("error_paths", [])
        body_patterns_cfg  = self.template.get("body_patterns", [])

        compiled_patterns = []
        for bp in body_patterns_cfg:
            try:
                compiled_patterns.append({
                    "re":         re.compile(bp["pattern"], re.IGNORECASE),
                    "technology": bp.get("technology", "Unknown"),
                    "severity":   bp.get("severity", "low"),
                })
            except re.error as e:
                reporter.warn("[version-disclosure] Bad pattern '{}': {}".format(
                    bp.get("pattern"), e))

        # Base URL list from engine + dedicated error probes
        base_urls  = list(urls) if urls else [target.url]
        error_urls = [target.origin + p for p in error_paths]
        all_urls   = list(dict.fromkeys(base_urls + error_urls))

        reporter.info("[version-disclosure] Checking {} page(s) + {} error probe(s)".format(
            len(base_urls), len(error_urls)))

        # hits[key] = [(url, cause_string)]
        hits = defaultdict(list)

        for url in all_urls:
            reporter.debug("  {}".format(url))
            try:
                resp = client.get(url)
            except (ConnectionError, TimeoutError) as e:
                reporter.debug("  skipped {}: {}".format(url, e))
                continue

            # Header vector
            for hname in disclosure_headers:
                hval = resp.headers.get(hname) or resp.headers.get(hname.lower())
                if hval:
                    key = ("header", hname, hval.strip())
                    hits[key].append((url, "{}: {}".format(hname, hval.strip())))

            # Body vector
            if resp.text:
                for pat in compiled_patterns:
                    for m in pat["re"].finditer(resp.text):
                        version = next((g for g in reversed(m.groups()) if g), m.group(0))
                        snippet = resp.text[max(0, m.start()-20):m.end()+20].strip()
                        snippet = " ".join(snippet.split())
                        key = ("body", pat["technology"], version)
                        hits[key].append((url, snippet))

        if not hits:
            reporter.info("[version-disclosure] No version disclosure found.")
            return

        for key, occurrences in sorted(hits.items(), key=lambda x: -len(x[1])):
            vector, label, value = key
            urls_affected = list(dict.fromkeys(u for u, _ in occurrences))

            sample    = urls_affected[:5]
            extra     = len(urls_affected) - len(sample)
            url_block = "\n              ".join(sample)
            if extra:
                url_block += "\n              ... and {} more".format(extra)

            if vector == "header":
                sev       = _header_severity(label, value)
                technique = "Response header disclosure"
                cause     = "{}: {}\n              Found on: {}".format(
                    label, value, url_block)
            else:
                pat_match = next((p for p in compiled_patterns
                                  if p["technology"] == label), None)
                sev       = pat_match["severity"] if pat_match else "low"
                technique = "Response body pattern match"
                cause     = "{} version string: {}\n              Context: ...{}...\n              Found on: {}".format(
                    label, value, occurrences[0][1], url_block)

            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "Version Disclosure — {} ({})".format(label, vector),
                severity    = sev,
                target      = target.url,
                affected    = urls_affected[0] if len(urls_affected) == 1
                              else "{} pages".format(len(urls_affected)),
                technique   = technique,
                cause       = cause,
            ))

        reporter.info("[version-disclosure] {} unique disclosure(s).".format(len(hits)))


def _header_severity(header_name: str, value: str) -> str:
    has_version = bool(re.search(r'\d+\.\d+', value))
    name_lower  = header_name.lower()
    if name_lower == "server":
        return "low" if has_version else "info"
    if name_lower in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        return "low"
    return "info"