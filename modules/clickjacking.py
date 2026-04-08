"""
modules/clickjacking.py
────────────────────────
Module: ClickjackingModule
Template: templates/clickjacking.yaml

Clickjacking detection logic
─────────────────────────────

Browsers enforce iframe embedding restrictions via two mechanisms:

  1. X-Frame-Options (XFO)  — legacy, HTTP header
       DENY          : blocks all framing                 ✓
       SAMEORIGIN    : blocks cross-origin framing        ✓
       ALLOW-FROM    : deprecated, IGNORED by Chrome/Firefox  ✗

  2. Content-Security-Policy: frame-ancestors  — modern, takes precedence
       frame-ancestors 'none'  : blocks all framing      ✓
       frame-ancestors 'self'  : same-origin only        ✓
       frame-ancestors <origin>: explicit allowlist       ✓
       absent                  : no CSP protection        ✗

Verdict matrix
──────────────
  XFO         | CSP frame-ancestors | Verdict
  ─────────────────────────────────────────────
  absent      | absent              | VULNERABLE
  ALLOW-FROM  | absent              | VULNERABLE  (deprecated, ignored by modern browsers)
  ALLOW-FROM  | present+restrictive | PROTECTED   (CSP covers what XFO can't)
  DENY/SAME   | absent              | PARTIAL     (legacy-browser safe, modern gap exists)
  DENY/SAME   | present+restrictive | PROTECTED
  absent      | present+restrictive | PROTECTED
"""

import re
from modules.base    import BaseModule
from core.target     import Target
from core.http_client import HttpClient
from core.reporter   import Reporter, Finding
from core.crawler    import crawl


# Directives we treat as "restrictive" in frame-ancestors
_RESTRICTIVE_ANCESTORS = {"'none'", "none", "'self'", "self"}

# Regex to extract frame-ancestors value from a CSP header
_FA_RE = re.compile(
    r"frame-ancestors\s+([^;]+)",
    re.IGNORECASE,
)


def _analyse_frame_ancestors(csp_value: str):
    """
    Parse the frame-ancestors directive from a CSP string.
    Returns (present: bool, restrictive: bool, raw_value: str)
    """
    if not csp_value:
        return False, False, ""

    m = _FA_RE.search(csp_value)
    if not m:
        return False, False, ""

    raw = m.group(1).strip()
    # Split on whitespace; check each token
    tokens = raw.lower().split()
    # Restrictive if it contains 'none', 'self', or a short explicit origin list
    # We treat anything that is NOT a wildcard (*) and NOT http:// without a host
    # as restrictive for the purposes of this check
    is_wildcard = "*" in tokens
    restrictive = not is_wildcard and len(tokens) > 0

    return True, restrictive, raw


def _assess(headers: dict) -> tuple:
    """
    Given a case-insensitive dict of response headers, return:
      (verdict, xfo_value, csp_fa_value, detail)

    verdict: "VULNERABLE" | "PARTIAL" | "PROTECTED"
    """
    headers_lower = {k.lower(): v for k, v in headers.items()}

    xfo = headers_lower.get("x-frame-options", "").strip().upper()
    csp = headers_lower.get("content-security-policy", "")

    fa_present, fa_restrictive, fa_raw = _analyse_frame_ancestors(csp)

    # ── CSP frame-ancestors takes precedence over XFO in modern browsers ── #
    if fa_present and fa_restrictive:
        return (
            "PROTECTED",
            xfo or "absent",
            fa_raw,
            "CSP frame-ancestors is present and restrictive. Modern browsers are protected.",
        )

    # ── CSP has frame-ancestors but it's a wildcard ── #
    if fa_present and not fa_restrictive:
        return (
            "VULNERABLE",
            xfo or "absent",
            fa_raw,
            "CSP frame-ancestors uses a wildcard — framing is unrestricted.",
        )

    # ── No CSP frame-ancestors — fall back to XFO logic ── #
    if not xfo or xfo == "ABSENT":
        return (
            "VULNERABLE",
            "absent",
            "absent",
            "Neither X-Frame-Options nor CSP frame-ancestors is set. "
            "Page can be freely embedded in an iframe.",
        )

    if "ALLOW-FROM" in xfo:
        return (
            "VULNERABLE",
            xfo,
            "absent",
            "X-Frame-Options: ALLOW-FROM is deprecated and ignored by Chrome and Firefox. "
            "No CSP frame-ancestors fallback is present. Page is embeddable in modern browsers.",
        )

    if xfo in ("DENY", "SAMEORIGIN"):
        return (
            "PARTIAL",
            xfo,
            "absent",
            "X-Frame-Options is set to {} but CSP frame-ancestors is absent. "
            "Protection relies solely on XFO, which is a legacy mechanism not "
            "supported in all contexts (e.g. nested workers, sandboxed iframes). "
            "Add CSP frame-ancestors for complete coverage.".format(xfo),
        )

    # Unknown XFO value — treat conservatively
    return (
        "PARTIAL",
        xfo,
        "absent",
        "X-Frame-Options has an unrecognised value: {}. CSP frame-ancestors is absent.".format(xfo),
    )


class ClickjackingModule(BaseModule):

    def run(self, target: Target, client: HttpClient, reporter: Reporter) -> None:
        crawl_depth = self.template.get("crawl_depth", 2)

        reporter.info("[clickjacking] Crawling {} (depth={})...".format(
            target.url, crawl_depth))

        urls = crawl(
            target,
            depth   = crawl_depth,
            timeout = client.timeout,
            proxy   = list(client.proxies.values())[0] if client.proxies else None,
            verbose = reporter.verbose,
        )

        reporter.info("[clickjacking] {} endpoint(s) to check".format(len(urls)))

        vulnerable = []
        partial    = []
        protected  = []

        for url in urls:
            reporter.debug("  checking {}".format(url))
            try:
                resp = client.get(url)
            except (ConnectionError, TimeoutError) as e:
                reporter.debug("  skipped {}: {}".format(url, e))
                continue

            verdict, xfo, fa, detail = _assess(resp.headers)

            if verdict == "VULNERABLE":
                vulnerable.append((url, xfo, fa, detail))
            elif verdict == "PARTIAL":
                partial.append((url, xfo, fa, detail))
            else:
                protected.append(url)

        reporter.debug("  results: {} vulnerable, {} partial, {} protected".format(
            len(vulnerable), len(partial), len(protected)))

        # ── Emit findings ──────────────────────────────────────────── #

        for url, xfo, fa, detail in vulnerable:
            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "Clickjacking — VULNERABLE",
                severity    = self.severity,
                target      = url,
                technique   = "iframe embedding check (XFO + CSP frame-ancestors)",
                evidence    = "X-Frame-Options: {}  |  CSP frame-ancestors: {}".format(xfo, fa),
                detail      = detail,
                remediation = self.remediation,
            ))

        for url, xfo, fa, detail in partial:
            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "Clickjacking — PARTIAL PROTECTION",
                severity    = "low",
                target      = url,
                technique   = "iframe embedding check (XFO + CSP frame-ancestors)",
                evidence    = "X-Frame-Options: {}  |  CSP frame-ancestors: {}".format(xfo, fa),
                detail      = detail,
                remediation = self.remediation,
            ))
