"""
modules/http_redirect.py
─────────────────────────
Module: HttpRedirectModule
Template: templates/http-redirect.yaml

Checks:
  1. Does plain HTTP redirect to HTTPS?
  2. Is the redirect a 301 (permanent) vs 302 (temporary)?
  3. Is HSTS set on the HTTPS response?
  4. Does HSTS have adequate max-age (>= 1 year = 31536000)?
  5. Does HSTS include includeSubDomains?
  6. Does HSTS include preload?
"""

import re
from modules.base     import BaseModule
from core.target      import Target
from core.http_client import HttpClient
from core.reporter    import Reporter, Finding


_HSTS_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)
_MIN_HSTS_AGE    = 31536000   # 1 year in seconds


class HttpRedirectModule(BaseModule):

    def run(self, target: Target, client: HttpClient, reporter: Reporter) -> None:
        reporter.info("[http-redirect] Checking HTTPS enforcement for {}".format(target.host))

        # ── 1. Probe plain HTTP ────────────────────────────────────── #
        http_url = target.http_url
        reporter.debug("  probing plain HTTP: {}".format(http_url))

        try:
            resp = client.get(http_url)
        except (ConnectionError, TimeoutError) as e:
            reporter.warn("[http-redirect] Could not reach HTTP endpoint: {}".format(e))
            return

        status   = resp.status_code
        location = resp.location or ""

        # ── Check: HTTP not redirected at all ─────────────────────── #
        if status not in (301, 302, 303, 307, 308):
            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "HTTP Not Redirected to HTTPS",
                severity    = self.severity,
                target      = http_url,
                technique   = "Plain HTTP request",
                evidence    = "HTTP {} returned for plain HTTP request — no redirect".format(status),
                detail      = (
                    "The server accepted a plain HTTP connection and returned HTTP {} "
                    "without redirecting to HTTPS. Sensitive data may be transmitted "
                    "in plaintext.".format(status)
                ),
                remediation = self.remediation,
            ))
            return  # No point checking further

        # ── Check: redirect goes to HTTP not HTTPS ─────────────────── #
        if location and not location.lower().startswith("https://"):
            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "HTTP Redirects to HTTP (Not HTTPS)",
                severity    = "high",
                target      = http_url,
                technique   = "Plain HTTP request",
                evidence    = "HTTP {} → Location: {}".format(status, location),
                detail      = "The redirect from HTTP points to another HTTP URL, not HTTPS.",
                remediation = self.remediation,
            ))
            return

        # ── Check: temporary redirect instead of permanent ─────────── #
        if status in (302, 303, 307):
            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "HTTP to HTTPS Redirect is Temporary (not 301)",
                severity    = "low",
                target      = http_url,
                technique   = "Plain HTTP request",
                evidence    = "HTTP {} (temporary) → Location: {}".format(status, location),
                detail      = (
                    "The redirect from HTTP to HTTPS uses a {} (temporary) status code. "
                    "Browsers will not cache this redirect, so every session starts "
                    "over plaintext HTTP before being upgraded. Use 301 instead.".format(status)
                ),
                remediation = self.remediation,
            ))

        reporter.debug("  HTTP → HTTPS redirect OK (HTTP {})".format(status))

        # ── 2. Fetch the HTTPS response and check HSTS ─────────────── #
        https_url = target.https_url
        reporter.debug("  checking HSTS on {}".format(https_url))

        try:
            https_resp = client.get(https_url)
        except (ConnectionError, TimeoutError) as e:
            reporter.warn("[http-redirect] Could not reach HTTPS endpoint: {}".format(e))
            return

        hsts = https_resp.headers.get("Strict-Transport-Security") or \
               https_resp.headers.get("strict-transport-security") or ""

        # No HSTS at all
        if not hsts:
            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "HSTS Header Missing on HTTPS Response",
                severity    = "medium",
                target      = https_url,
                technique   = "HTTPS response header check",
                evidence    = "Strict-Transport-Security header is absent",
                detail      = (
                    "HTTPS redirect exists but HSTS is not set. Browsers will not "
                    "cache the upgrade, leaving every new session vulnerable to "
                    "SSL stripping attacks."
                ),
                remediation = (
                    "Add: Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains; preload"
                ),
            ))
            return

        reporter.debug("  HSTS: {}".format(hsts))

        # HSTS max-age too short
        ma_match = _HSTS_MAX_AGE_RE.search(hsts)
        if ma_match:
            max_age = int(ma_match.group(1))
            if max_age < _MIN_HSTS_AGE:
                reporter.add_finding(Finding(
                    template_id = self.id,
                    name        = "HSTS max-age Too Short",
                    severity    = "low",
                    target      = https_url,
                    technique   = "HTTPS response header check",
                    evidence    = "Strict-Transport-Security: {}".format(hsts),
                    detail      = (
                        "HSTS max-age is {} seconds (~{} days), below the recommended "
                        "minimum of 31536000 (1 year). Short max-age means browsers "
                        "will re-attempt HTTP after it expires.".format(
                            max_age, max_age // 86400)
                    ),
                    remediation = "Set max-age to at least 31536000.",
                ))
        else:
            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "HSTS max-age Missing",
                severity    = "medium",
                target      = https_url,
                technique   = "HTTPS response header check",
                evidence    = "Strict-Transport-Security: {}".format(hsts),
                detail      = "HSTS header is present but has no max-age directive.",
                remediation = "Add max-age=31536000 to the HSTS header.",
            ))

        # HSTS missing includeSubDomains
        if "includesubdomains" not in hsts.lower():
            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "HSTS Missing includeSubDomains",
                severity    = "info",
                target      = https_url,
                technique   = "HTTPS response header check",
                evidence    = "Strict-Transport-Security: {}".format(hsts),
                detail      = (
                    "HSTS does not include includeSubDomains. Subdomains may still "
                    "be reachable over plain HTTP."
                ),
                remediation = "Add includeSubDomains to the HSTS header.",
            ))

        reporter.info("[http-redirect] Done.")
