"""
modules/clickjacking.py
Module: ClickjackingModule

Receives a pre-crawled, HTML-filtered URL list from the engine.
"""

import re
from modules.base     import BaseModule
from core.target      import Target
from core.http_client import HttpClient
from core.reporter    import Reporter, Finding

_FA_RE = re.compile(r"frame-ancestors\s+([^;]+)", re.IGNORECASE)


def _analyse_frame_ancestors(csp_value: str):
    if not csp_value:
        return False, False, ""
    m = _FA_RE.search(csp_value)
    if not m:
        return False, False, ""
    raw         = m.group(1).strip()
    tokens      = raw.lower().split()
    is_wildcard = "*" in tokens
    restrictive = not is_wildcard and len(tokens) > 0
    return True, restrictive, raw


def _assess(headers: dict) -> tuple:
    """Returns (verdict, cause_string). verdict: VULNERABLE | PARTIAL | PROTECTED"""
    hl  = {k.lower(): v for k, v in headers.items()}
    xfo = hl.get("x-frame-options", "").strip().upper()
    csp = hl.get("content-security-policy", "")

    fa_present, fa_restrictive, fa_raw = _analyse_frame_ancestors(csp)

    if fa_present and fa_restrictive:
        return ("PROTECTED",
                "X-Frame-Options: {}  |  CSP frame-ancestors: {}".format(xfo or "absent", fa_raw))

    if fa_present and not fa_restrictive:
        return ("VULNERABLE",
                "CSP frame-ancestors: {} (wildcard — framing unrestricted)".format(fa_raw))

    if not xfo:
        return ("VULNERABLE",
                "X-Frame-Options: absent  |  CSP frame-ancestors: absent")

    if "ALLOW-FROM" in xfo:
        return ("VULNERABLE",
                "X-Frame-Options: {}  |  CSP frame-ancestors: absent  "
                "(ALLOW-FROM deprecated — Chrome/Firefox ignore it)".format(xfo))

    if xfo in ("DENY", "SAMEORIGIN"):
        return ("PARTIAL",
                "X-Frame-Options: {}  |  CSP frame-ancestors: absent  "
                "(XFO-only protection — no coverage in some modern browser contexts)".format(xfo))

    return ("PARTIAL",
            "X-Frame-Options: {}  |  CSP frame-ancestors: absent".format(xfo))


class ClickjackingModule(BaseModule):

    def run(self, target: Target, client: HttpClient,
            reporter: Reporter, urls: list = None) -> None:

        if not urls:
            reporter.info("[clickjacking] No URLs to check.")
            return

        reporter.info("[clickjacking] Checking {} page(s)".format(len(urls)))

        for url in urls:
            reporter.debug("  {}".format(url))
            try:
                resp = client.get(url)
            except (ConnectionError, TimeoutError) as e:
                reporter.debug("  skipped {}: {}".format(url, e))
                continue

            verdict, cause = _assess(resp.headers)

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

        reporter.info("[clickjacking] Done.")