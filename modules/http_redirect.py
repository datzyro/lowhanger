"""
modules/http_redirect.py
Module: HttpRedirectModule
"""

from modules.base     import BaseModule
from core.target      import Target
from core.http_client import HttpClient
from core.reporter    import Reporter, Finding


class HttpRedirectModule(BaseModule):

    def run(self, target: Target, client: HttpClient, reporter: Reporter, urls: list = None) -> None:
        reporter.info("[http-redirect] Checking HTTPS enforcement for {}".format(target.host))

        http_url = target.http_url

        try:
            resp = client.get(http_url)
        except (ConnectionError, TimeoutError) as e:
            reporter.warn("[http-redirect] Could not reach HTTP endpoint: {}".format(e))
            return

        status   = resp.status_code
        location = resp.location or ""

        # HTTP not redirected at all
        if status not in (301, 302, 303, 307, 308):
            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "HTTP Not Redirected to HTTPS",
                severity    = self.severity,
                target      = target.url,
                affected    = http_url,
                technique   = "Plain HTTP request",
                cause       = "HTTP {} — server accepted plain HTTP, no redirect issued".format(status),
            ))
            return

        # Redirect goes to HTTP not HTTPS
        if location and not location.lower().startswith("https://"):
            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "HTTP Redirects to HTTP (Not HTTPS)",
                severity    = "high",
                target      = target.url,
                affected    = http_url,
                technique   = "Plain HTTP request",
                cause       = "HTTP {} → Location: {}".format(status, location),
            ))
            return

        # Temporary redirect instead of permanent
        if status in (302, 303, 307):
            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "HTTP to HTTPS Redirect is Temporary",
                severity    = "low",
                target      = target.url,
                affected    = http_url,
                technique   = "Plain HTTP request",
                cause       = "HTTP {} (temporary) → Location: {}".format(status, location),
            ))

        # Check HSTS on HTTPS response
        https_url = target.https_url
        try:
            https_resp = client.get(https_url)
        except (ConnectionError, TimeoutError) as e:
            reporter.warn("[http-redirect] Could not reach HTTPS endpoint: {}".format(e))
            return

        hsts = (https_resp.headers.get("Strict-Transport-Security")
                or https_resp.headers.get("strict-transport-security")
                or "")

        if not hsts:
            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "HSTS Header Missing",
                severity    = "medium",
                target      = target.url,
                affected    = https_url,
                technique   = "HTTPS response header check",
                cause       = "Strict-Transport-Security header absent from HTTPS response",
            ))
            return

        reporter.info("[http-redirect] Done.")
