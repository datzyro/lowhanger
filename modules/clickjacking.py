"""
modules/clickjacking.py
Module: ClickjackingModule
"""

import re
from modules.base     import BaseModule
from core.target      import Target
from core.http_client import HttpClient
from core.reporter    import Reporter, Finding
from core.crawler     import crawl

_FA_RE = re.compile(r"frame-ancestors\s+([^;]+)", re.IGNORECASE)


def _analyse_frame_ancestors(csp_value: str):
    if not csp_value:
        return False, False, ""
    m = _FA_RE.search(csp_value)
    if not m:
        return False, False, ""
    raw       = m.group(1).strip()
    tokens    = raw.lower().split()
    is_wildcard  = "*" in tokens
    restrictive  = not is_wildcard and len(tokens) > 0
    return True, restrictive, raw


def _assess(headers: dict) -> tuple:
    """Returns (verdict, xfo_value, csp_fa_value, cause_string)"""
    hl  = {k.lower(): v for k, v in headers.items()}
    xfo = hl.get("x-frame-options", "").strip().upper()
    csp = hl.get("content-security-policy", "")

    fa_present, fa_restrictive, fa_raw = _analyse_frame_ancestors(csp)

    if fa_present and fa_restrictive:
        return ("PROTECTED", xfo or "absent", fa_raw,
                "X-Frame-Options: {}  |  CSP frame-ancestors: {}".format(xfo or "absent", fa_raw))

    if fa_present and not fa_restrictive:
        return ("VULNERABLE", xfo or "absent", fa_raw,
                "CSP frame-ancestors: {} (wildcard — unrestricted framing)".format(fa_raw))

    if not xfo:
        return ("VULNERABLE", "absent", "absent",
                "X-Frame-Options: absent  |  CSP frame-ancestors: absent")

    if "ALLOW-FROM" in xfo:
        return ("VULNERABLE", xfo, "absent",
                "X-Frame-Options: {}  |  CSP frame-ancestors: absent  "
                "(ALLOW-FROM is deprecated — ignored by Chrome/Firefox)".format(xfo))

    if xfo in ("DENY", "SAMEORIGIN"):
        return ("PARTIAL", xfo, "absent",
                "X-Frame-Options: {}  |  CSP frame-ancestors: absent  "
                "(legacy-only protection — modern browsers may not enforce XFO in all contexts)".format(xfo))

    return ("PARTIAL", xfo, "absent",
            "X-Frame-Options: {}  |  CSP frame-ancestors: absent".format(xfo))


class ClickjackingModule(BaseModule):

    def run(self, target: Target, client: HttpClient, reporter: Reporter) -> None:
        crawl_depth = self.template.get("crawl_depth", 2)

        reporter.info("[clickjacking] Crawling {} (depth={})...".format(target.url, crawl_depth))
        urls = crawl(target, depth=crawl_depth, timeout=client.timeout,
                     proxy=list(client.proxies.values())[0] if client.proxies else None,
                     verbose=reporter.verbose)

        reporter.info("[clickjacking] {} endpoint(s) to check".format(len(urls)))

        for url in urls:
            reporter.debug("  checking {}".format(url))
            try:
                resp = client.get(url)
            except (ConnectionError, TimeoutError) as e:
                reporter.debug("  skipped {}: {}".format(url, e))
                continue

            verdict, xfo, fa, cause = _assess(resp.headers)

            if verdict == "PROTECTED":
                continue

            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "Clickjacking — {}".format(verdict),
                severity    = self.severity if verdict == "VULNERABLE" else "low",
                target      = target.url,
                affected    = url,
                technique   = "iframe embedding check (X-Frame-Options + CSP frame-ancestors)",
                cause       = cause,
            ))