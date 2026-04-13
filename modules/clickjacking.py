"""
modules/clickjacking.py
Module: ClickjackingModule

Verifies clickjacking by actually attempting to load the page inside an
iframe using a headless browser (Playwright). This is the only reliable
method — header checks alone can give false positives (JS frame-busting)
and false negatives (ALLOW-FROM ignored by Chrome/Firefox).

Strategy
────────
For each HTML page in the URL list:

  Phase 1 — Header pre-filter (free, no browser)
    Skip the page entirely if it has unambiguous server-side protection:
      • CSP frame-ancestors 'none' or 'self' (restrictive, non-wildcard)
      • X-Frame-Options: DENY or SAMEORIGIN
    These are treated as protected and not tested further.

    Pages with NO protection, ALLOW-FROM (deprecated), or wildcard
    CSP frame-ancestors proceed to Phase 2.

  Phase 2 — Actual iframe load attempt (Playwright headless Chromium)
    An in-memory HTML page with <iframe src="URL"> is loaded.
    After a short wait, we check whether the iframe's contentDocument
    is accessible and has a non-empty body — this is what a real
    attacker would see.

    If the iframe content is accessible → VULNERABLE, emit finding, STOP.

  Fallback (Playwright not installed)
    Phase 1 pre-filter only. Pages that pass Phase 1 (no server-side
    protection and no JS frame-busting patterns in body) are flagged
    as VULNERABLE. First match only, then stop.

Output
──────
  • ONE single finding maximum per target scan.
  • Only VULNERABLE is reported. PARTIAL removed entirely.
  • Stops immediately after the first confirmed vulnerable page.
"""

import re
import shutil
from modules.base     import BaseModule
from core.target      import Target
from core.http_client import HttpClient
from core.reporter    import Reporter, Finding


# ── Header assessment ─────────────────────────────────────────────────────

_FA_RE = re.compile(r"frame-ancestors\s+([^;]+)", re.IGNORECASE)

# Common JS frame-busting patterns — if found in body, skip the page
# (browser test would be definitive but we use this as a fallback hint)
_FRAMEBUST_RE = re.compile(
    r"(top\.location\s*!==?|self\s*!==?\s*top|parent\.location|"
    r"window\.top\s*!==?\s*window\.self|top\s*!==?\s*self)",
    re.IGNORECASE,
)


def _header_verdict(headers: dict) -> str:
    """
    Returns:
      "PROTECTED"  — strong server-side protection, skip iframe test
      "CANDIDATE"  — no/weak protection, proceed to iframe test
    """
    hl  = {k.lower(): v for k, v in headers.items()}
    xfo = hl.get("x-frame-options", "").strip().upper()
    csp = hl.get("content-security-policy", "")

    # Check CSP frame-ancestors
    m = _FA_RE.search(csp)
    if m:
        raw    = m.group(1).strip().lower()
        tokens = raw.split()
        # Wildcard or empty = no real protection
        if "*" not in tokens and tokens:
            return "PROTECTED"   # 'none', 'self', or explicit origin list

    # ALLOW-FROM is deprecated and ignored by Chrome/Firefox — treat as candidate
    if xfo in ("DENY", "SAMEORIGIN"):
        return "PROTECTED"

    return "CANDIDATE"


# ── Playwright iframe verification ────────────────────────────────────────

def _try_import_playwright():
    try:
        from playwright.sync_api import sync_playwright
        return sync_playwright
    except ImportError:
        return None


_IFRAME_TEST_HTML = """
<!DOCTYPE html>
<html>
<head><title>lowhanger iframe test</title></head>
<body>
<iframe id="target" src="{url}" style="width:1px;height:1px;"
        sandbox="allow-same-origin allow-scripts"></iframe>
</body>
</html>
"""

def _playwright_iframe_test(url: str, timeout_ms: int = 6000) -> tuple:
    """
    Load the URL inside an iframe using Playwright headless Chromium.

    Returns (embeddable: bool, detail: str)
      embeddable=True  → iframe content loaded and body is accessible
      embeddable=False → browser blocked the iframe or content is empty
    """
    sync_playwright = _try_import_playwright()
    if sync_playwright is None:
        return None, "playwright not installed"

    html_content = _IFRAME_TEST_HTML.format(url=url)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page    = browser.new_page()

            # Set the test page content directly — no need to serve it
            page.set_content(html_content, wait_until="domcontentloaded")
            page.wait_for_timeout(timeout_ms)

            # Try to access iframe's contentDocument from JS
            # If framing is blocked, this will throw or return null/empty
            result = page.evaluate("""
                () => {
                    try {
                        const iframe = document.getElementById('target');
                        if (!iframe) return {blocked: true, reason: 'no iframe element'};
                        const doc = iframe.contentDocument || iframe.contentWindow.document;
                        if (!doc) return {blocked: true, reason: 'contentDocument null'};
                        const body = doc.body;
                        if (!body) return {blocked: true, reason: 'body null'};
                        const text = body.innerText || body.textContent || '';
                        const html = body.innerHTML || '';
                        return {
                            blocked: false,
                            bodyLength: html.length,
                            snippet: text.trim().substring(0, 120)
                        };
                    } catch(e) {
                        return {blocked: true, reason: e.toString()};
                    }
                }
            """)

            browser.close()

            if result.get("blocked"):
                return False, "iframe blocked: {}".format(result.get("reason", "unknown"))

            body_len = result.get("bodyLength", 0)
            snippet  = result.get("snippet", "")

            if body_len < 10:
                return False, "iframe loaded but body is empty ({}B)".format(body_len)

            return True, "iframe content accessible — body {}B: {}{}".format(
                body_len,
                snippet[:80],
                "..." if len(snippet) > 80 else "",
            )

    except Exception as e:
        return False, "playwright error: {}".format(str(e))


# ── Fallback: header + JS frame-bust scan ────────────────────────────────

def _fallback_check(resp) -> tuple:
    """
    When Playwright is unavailable, use response body to look for
    JS frame-busting code. If found, the page probably protects itself
    at the JS level even without headers — skip it.

    Returns (vulnerable: bool, detail: str)
    """
    body = resp.text or ""
    if _FRAMEBUST_RE.search(body):
        return False, "JS frame-busting code detected in response body"
    return True, "no server-side header protection and no JS frame-busting detected"


# ── Module ────────────────────────────────────────────────────────────────

class ClickjackingModule(BaseModule):

    def run(self, target: Target, client: HttpClient,
            reporter: Reporter, urls: list = None) -> None:

        if not urls:
            reporter.info("[clickjacking] No URLs to check.")
            return

        has_playwright = _try_import_playwright() is not None
        method = "Playwright headless Chromium iframe test" if has_playwright \
                 else "Header check + JS frame-bust scan (install playwright for full verification)"

        reporter.info("[clickjacking] {} page(s) — method: {}".format(
            len(urls), "playwright" if has_playwright else "fallback"))

        for url in urls:
            reporter.debug("  {}".format(url))

            # ── Phase 1: header pre-filter ──────────────────────────── #
            try:
                resp = client.get(url)
            except (ConnectionError, TimeoutError) as e:
                reporter.debug("  skipped {}: {}".format(url, e))
                continue

            verdict = _header_verdict(resp.headers)
            if verdict == "PROTECTED":
                reporter.debug("  {} — headers protected, skipping".format(url))
                continue

            hl  = {k.lower(): v for k, v in resp.headers.items()}
            xfo = hl.get("x-frame-options", "absent")
            csp_fa = "absent"
            m = _FA_RE.search(hl.get("content-security-policy", ""))
            if m:
                csp_fa = m.group(1).strip()

            header_summary = "X-Frame-Options: {}  |  CSP frame-ancestors: {}".format(
                xfo, csp_fa)

            # ── Phase 2: actual iframe verification ─────────────────── #
            if has_playwright:
                reporter.debug("  {} — running iframe test".format(url))
                embeddable, detail = _playwright_iframe_test(url)

                if embeddable is None:
                    reporter.debug("  playwright unavailable, falling back")
                    vulnerable, detail = _fallback_check(resp)
                else:
                    vulnerable = embeddable
            else:
                vulnerable, detail = _fallback_check(resp)

            if not vulnerable:
                reporter.debug("  {} — not embeddable: {}".format(url, detail))
                continue

            # ── Confirmed vulnerable — emit single finding and stop ── #
            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "Clickjacking — VULNERABLE",
                severity    = self.severity,
                target      = target.url,
                affected    = url,
                technique   = method,
                cause       = "{}  |  {}".format(header_summary, detail),
            ))

            reporter.info("[clickjacking] Confirmed vulnerable at {} — stopping.".format(url))
            return   # ← stop after first confirmed finding

        reporter.info("[clickjacking] No confirmed clickjacking vulnerability found.")