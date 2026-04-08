"""
modules/cors.py
────────────────
Module: CorsModule
Template: templates/cors.yaml

CORS misconfiguration testing across all crawled endpoints.

Test matrix (per endpoint, per origin probe):
  ┌─────────────────────────────────────────────┬───────────────────────────┬──────────┐
  │ ACAO response                               │ ACAC response             │ Severity │
  ├─────────────────────────────────────────────┼───────────────────────────┼──────────┤
  │ reflects attacker origin                    │ true                      │ CRITICAL │
  │ reflects attacker origin                    │ absent/false              │ HIGH     │
  │ *                                           │ true (spec-invalid)       │ MEDIUM   │
  │ *                                           │ absent/false              │ LOW      │
  │ null                                        │ true                      │ LOW      │
  │ reflects subdomain-confusion origin         │ any                       │ HIGH/CRIT│
  └─────────────────────────────────────────────┴───────────────────────────┴──────────┘

De-duplication: same (origin_probe, acao_value, acac_value) on same URL reported once.
"""

from collections import defaultdict
from modules.base     import BaseModule
from core.target      import Target
from core.http_client import HttpClient
from core.reporter    import Reporter, Finding
from core.crawler     import crawl


_CRED_HEADER = "access-control-allow-credentials"
_ACAO_HEADER = "access-control-allow-origin"


def _normalise_headers(headers) -> dict:
    return {k.lower(): v.strip() for k, v in headers.items()}


def _credentials_true(headers: dict) -> bool:
    return headers.get(_CRED_HEADER, "").lower() == "true"


def _classify(acao: str, has_credentials: bool, injected_origin: str) -> tuple:
    """
    Returns (severity, issue_label, detail) or (None, None, None) if benign.

    acao             : value of Access-Control-Allow-Origin
    has_credentials  : whether ACAC: true is set
    injected_origin  : the Origin value we sent
    """
    if not acao:
        return None, None, None

    acao_lower = acao.strip().lower()

    # ── Reflected origin ─────────────────────────────────────────── #
    if acao.strip().rstrip("/") == injected_origin.rstrip("/"):
        if has_credentials:
            return (
                "critical",
                "Reflected Origin + Credentials",
                (
                    "The server reflects the attacker-controlled Origin header "
                    "({}) back in Access-Control-Allow-Origin AND sets "
                    "Access-Control-Allow-Credentials: true. An attacker can "
                    "make credentialed cross-origin requests (with cookies, "
                    "session tokens) and read the response — this is the most "
                    "severe CORS misconfiguration.".format(injected_origin)
                ),
            )
        else:
            return (
                "high",
                "Reflected Origin (no credentials)",
                (
                    "The server reflects the attacker-controlled Origin header "
                    "({}) in Access-Control-Allow-Origin. An attacker can read "
                    "cross-origin responses without credentials. If the endpoint "
                    "returns sensitive data this is directly exploitable.".format(injected_origin)
                ),
            )

    # ── Wildcard ─────────────────────────────────────────────────── #
    if acao_lower == "*":
        if has_credentials:
            return (
                "medium",
                "Wildcard ACAO + Credentials (spec-invalid, check parser behaviour)",
                (
                    "ACAO: * is set alongside ACAC: true. The CORS spec prohibits "
                    "this combination — browsers should reject it. However, some "
                    "non-browser HTTP clients and misconfigured parsers may honour it. "
                    "Test with a browser to confirm real-world exploitability."
                ),
            )
        else:
            return (
                "low",
                "Wildcard ACAO (public CORS)",
                (
                    "Access-Control-Allow-Origin: * permits any origin to read "
                    "responses from this endpoint. This is often intentional for "
                    "public APIs but should be verified — confirm no sensitive data "
                    "is returned and that credentials are never allowed."
                ),
            )

    # ── null origin ──────────────────────────────────────────────── #
    if acao_lower == "null" and injected_origin == "null":
        if has_credentials:
            return (
                "low",
                "null Origin Accepted + Credentials",
                (
                    "The server accepts the 'null' origin with credentials enabled. "
                    "Sandboxed iframes (e.g. <iframe sandbox>) send a null origin — "
                    "an attacker can exploit this by hosting a sandboxed iframe "
                    "that makes credentialed requests and reads the response."
                ),
            )

    return None, None, None


class CorsModule(BaseModule):

    def run(self, target: Target, client: HttpClient, reporter: Reporter) -> None:
        crawl_depth       = self.template.get("crawl_depth", 3)
        test_origins      = self.template.get("test_origins",
                                              ["https://evil.lowhanger.internal"])
        subdomain_bypass  = self.template.get("subdomain_bypass", True)
        test_null_origin  = self.template.get("test_null_origin", True)

        # ── Build full origin list ─────────────────────────────────── #
        origins_to_test = list(test_origins)

        if subdomain_bypass:
            # suffix match bypass: https://<target>.evil.com
            # prefix match bypass: https://evil.<target>
            origins_to_test.append(
                "https://{}.evil.lowhanger.internal".format(target.host))
            origins_to_test.append(
                "https://evil.{}".format(target.host))

        if test_null_origin:
            origins_to_test.append("null")

        # Deduplicate while preserving order
        origins_to_test = list(dict.fromkeys(origins_to_test))

        # ── Crawl ──────────────────────────────────────────────────── #
        reporter.info("[cors] Crawling {} (depth={})...".format(
            target.url, crawl_depth))

        urls = crawl(
            target,
            depth   = crawl_depth,
            timeout = client.timeout,
            proxy   = list(client.proxies.values())[0] if client.proxies else None,
            verbose = reporter.verbose,
        )

        reporter.info("[cors] {} endpoint(s) × {} origin(s) to test".format(
            len(urls), len(origins_to_test)))

        # ── Test each endpoint × each origin ─────────────────────── #
        # De-dupe key: (url, acao_value, acac_value) so we don't report
        # the same policy multiple times if two different origin probes
        # trigger the same response.
        seen = set()

        for url in urls:
            for origin in origins_to_test:
                reporter.debug("  {} ← Origin: {}".format(url, origin))

                try:
                    resp = client.get(url, headers={"Origin": origin})
                except (ConnectionError, TimeoutError) as e:
                    reporter.debug("  skipped {}: {}".format(url, e))
                    break   # if URL is unreachable, skip remaining origins for it

                h = _normalise_headers(resp.headers)
                acao = h.get(_ACAO_HEADER, "")
                acac = h.get(_CRED_HEADER, "")
                has_creds = acac.lower() == "true"

                if not acao:
                    reporter.debug("    no ACAO header")
                    continue

                severity, label, detail = _classify(acao, has_creds, origin)
                if severity is None:
                    reporter.debug("    ACAO: {} — benign".format(acao))
                    continue

                dedup_key = (url, acao, acac)
                if dedup_key in seen:
                    reporter.debug("    duplicate — skipping")
                    continue
                seen.add(dedup_key)

                evidence_parts = ["Origin sent: {}".format(origin),
                                  "ACAO: {}".format(acao)]
                if acac:
                    evidence_parts.append("ACAC: {}".format(acac))

                reporter.add_finding(Finding(
                    template_id = self.id,
                    name        = "{} — {}".format(self.name, label),
                    severity    = severity,
                    target      = url,
                    technique   = "CORS origin injection (Origin: {})".format(origin),
                    evidence    = "  |  ".join(evidence_parts),
                    detail      = detail,
                    remediation = self.remediation,
                ))

        reporter.info("[cors] Done.")
