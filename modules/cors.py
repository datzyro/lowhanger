"""
modules/cors.py
Module: CorsModule

Receives a pre-crawled, HTML-filtered URL list from the engine.
"""

from modules.base     import BaseModule
from core.target      import Target
from core.http_client import HttpClient
from core.reporter    import Reporter, Finding

_CRED_HEADER = "access-control-allow-credentials"
_ACAO_HEADER = "access-control-allow-origin"


def _normalise(headers) -> dict:
    return {k.lower(): v.strip() for k, v in headers.items()}


def _classify(acao: str, has_credentials: bool, injected_origin: str):
    """Returns (severity, name, cause) or (None, None, None) if benign."""
    if not acao:
        return None, None, None

    acao_lower = acao.strip().lower()

    if acao.strip().rstrip("/") == injected_origin.rstrip("/"):
        if has_credentials:
            return ("critical",
                    "CORS — Reflected Origin + Credentials",
                    "Origin: {}  →  ACAO: {}  |  ACAC: true".format(injected_origin, acao))
        return ("high",
                "CORS — Reflected Origin",
                "Origin: {}  →  ACAO: {}".format(injected_origin, acao))

    if acao_lower == "*":
        if has_credentials:
            return ("medium",
                    "CORS — Wildcard ACAO + Credentials (spec-invalid)",
                    "ACAO: *  |  ACAC: true")
        return ("low",
                "CORS — Wildcard ACAO",
                "ACAO: *")

    if acao_lower == "null" and injected_origin == "null":
        if has_credentials:
            return ("low",
                    "CORS — null Origin + Credentials",
                    "Origin: null  →  ACAO: null  |  ACAC: true  (sandboxed iframe bypass)")

    return None, None, None


class CorsModule(BaseModule):

    def run(self, target: Target, client: HttpClient,
            reporter: Reporter, urls: list = None) -> None:

        test_origins     = self.template.get("test_origins", ["https://evil.lowhanger.internal"])
        subdomain_bypass = self.template.get("subdomain_bypass", True)
        test_null        = self.template.get("test_null_origin", True)

        origins = list(test_origins)
        if subdomain_bypass:
            origins.append("https://{}.evil.lowhanger.internal".format(target.host))
            origins.append("https://evil.{}".format(target.host))
        if test_null:
            origins.append("null")
        origins = list(dict.fromkeys(origins))

        if not urls:
            reporter.info("[cors] No URLs to check.")
            return

        reporter.info("[cors] Checking {} page(s) × {} origin(s)".format(
            len(urls), len(origins)))

        seen = set()

        for url in urls:
            for origin in origins:
                reporter.debug("  {} ← Origin: {}".format(url, origin))
                try:
                    resp = client.get(url, headers={"Origin": origin})
                except (ConnectionError, TimeoutError) as e:
                    reporter.debug("  skipped {}: {}".format(url, e))
                    break

                h         = _normalise(resp.headers)
                acao      = h.get(_ACAO_HEADER, "")
                acac      = h.get(_CRED_HEADER, "")
                has_creds = acac.lower() == "true"

                if not acao:
                    continue

                severity, name, cause = _classify(acao, has_creds, origin)
                if severity is None:
                    continue

                dedup_key = (url, acao, acac)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                reporter.add_finding(Finding(
                    template_id = self.id,
                    name        = name,
                    severity    = severity,
                    target      = target.url,
                    affected    = url,
                    technique   = "CORS origin injection",
                    cause       = cause,
                ))

        reporter.info("[cors] Done.")