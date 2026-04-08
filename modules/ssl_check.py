"""
modules/ssl_check.py
─────────────────────
Module: SslCheckModule
Template: templates/ssl-check.yaml

Checks for deprecated TLS 1.0 and TLS 1.1 support only.

A finding is raised ONLY when testssl.sh reports:
  TLS 1    offered (deprecated)
  TLS 1.1  offered (deprecated)

Any other output for those entries ("not offered", warnings, errors, etc.)
is silently ignored. No other testssl.sh findings are processed.

Python fallback: only flags if the TLS 1.0 / TLS 1.1 handshake
actually completes successfully (server accepted the connection).
"""

import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
from modules.base     import BaseModule
from core.target      import Target
from core.http_client import HttpClient
from core.reporter    import Reporter, Finding


# The only two testssl.sh entry IDs we care about, mapped to human labels
WATCHED_IDS = {
    "tls1":   "TLS 1.0",
    "tls1_1": "TLS 1.1",
}

# The exact finding substring that marks a protocol as offered
OFFERED_MARKER = "offered (deprecated)"


class SslCheckModule(BaseModule):

    def run(self, target: Target, client: HttpClient, reporter: Reporter) -> None:
        host = target.host
        port = target.port or 443

        reporter.info("[ssl-check] Checking for deprecated TLS on {}:{}".format(host, port))

        testssl_path = self.template.get("testssl_path", "").strip()
        if not testssl_path:
            testssl_path = shutil.which("testssl.sh") or shutil.which("testssl")

        if testssl_path:
            reporter.info("[ssl-check] Using testssl.sh: {}".format(testssl_path))
            self._run_testssl(host, port, testssl_path, target, reporter)
        else:
            reporter.info("[ssl-check] testssl.sh not found — using Python fallback probe")
            reporter.info("[ssl-check] Install testssl.sh for accurate results: https://testssl.sh")
            self._run_python_probe(host, port, target, reporter)

    # ──────────────────────────────────────────────────────────────────── #
    # testssl.sh path                                                      #
    # ──────────────────────────────────────────────────────────────────── #

    def _run_testssl(self, host, port, testssl_path, target, reporter):
        json_file = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        json_file.close()

        cmd = [
            testssl_path,
            "--protocols",
            "--jsonfile", json_file.name,
            "--color",    "0",
            "--quiet",
            "{}:{}".format(host, port),
        ]

        reporter.debug("  testssl cmd: {}".format(" ".join(cmd)))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if reporter.verbose and result.stderr:
                reporter.debug("  testssl stderr: {}".format(result.stderr[:500]))
        except subprocess.TimeoutExpired:
            reporter.warn("[ssl-check] testssl.sh timed out after 5 minutes.")
            return
        except Exception as e:
            reporter.error("[ssl-check] testssl.sh failed: {}".format(e))
            return
        finally:
            findings = self._parse_testssl_json(json_file.name, target, reporter)
            try:
                os.unlink(json_file.name)
            except Exception:
                pass

        for f in findings:
            reporter.add_finding(f)

        if not findings:
            reporter.info("[ssl-check] TLS 1.0 and TLS 1.1 are not offered. No issues.")

    def _parse_testssl_json(self, json_path, target, reporter) -> list:
        findings = []

        try:
            with open(json_path) as fh:
                data = json.load(fh)
        except Exception as e:
            reporter.warn("[ssl-check] Could not parse testssl JSON: {}".format(e))
            return findings

        # testssl.sh writes either a flat list or a nested scanResult structure
        entries = (
            data
            if isinstance(data, list)
            else data.get("scanResult", [{}])[0].get("findings", [])
        )

        for entry in entries:
            entry_id = entry.get("id", "").lower().strip()
            finding  = entry.get("finding", "").lower().strip()

            # Only care about tls1 and tls1_1
            if entry_id not in WATCHED_IDS:
                continue

            # Only flag when the finding is exactly "offered (deprecated)"
            if OFFERED_MARKER not in finding:
                reporter.debug("  [ssl-check] {} → '{}' (not offered, skipping)".format(
                    entry_id, entry.get("finding", "")))
                continue

            label = WATCHED_IDS[entry_id]
            reporter.debug("  [ssl-check] {} → OFFERED (deprecated) — flagging".format(entry_id))

            findings.append(Finding(
                template_id = self.id,
                name        = "Deprecated Protocol Offered — {}".format(label),
                severity    = "medium",
                target      = target.url,
                technique   = "testssl.sh --protocols",
                evidence    = "{} offered (deprecated) on {}:{}".format(label, target.host, target.port or 443),
                detail      = (
                    "{} is deprecated and should not be offered. "
                    "PCI DSS has required its removal since June 2018. "
                    "Clients negotiating this version are vulnerable to "
                    "downgrade attacks.".format(label)
                ),
                remediation = self.remediation,
            ))

        return findings

    # ──────────────────────────────────────────────────────────────────── #
    # Python fallback — direct handshake probe for TLS 1.0 and 1.1 only  #
    # ──────────────────────────────────────────────────────────────────── #

    def _run_python_probe(self, host, port, target, reporter):
        probes = [
            ("TLS 1.0",  ssl.TLSVersion.TLSv1),
            ("TLS 1.1",  ssl.TLSVersion.TLSv1_1),
        ]

        any_found = False

        for label, version in probes:
            reporter.debug("  probing {}".format(label))
            offered, err = self._probe_tls_version(host, port, version)

            if offered:
                any_found = True
                reporter.add_finding(Finding(
                    template_id = self.id,
                    name        = "Deprecated Protocol Offered — {}".format(label),
                    severity    = "medium",
                    target      = target.url,
                    technique   = "Direct TLS handshake probe ({})".format(label),
                    evidence    = "{} handshake accepted on {}:{}".format(label, host, port),
                    detail      = (
                        "{} is deprecated and should not be offered. "
                        "PCI DSS has required its removal since June 2018. "
                        "Clients negotiating this version are vulnerable to "
                        "downgrade attacks.".format(label)
                    ),
                    remediation = self.remediation,
                ))
            else:
                reporter.debug("  {} not offered: {}".format(label, err))

        if not any_found:
            reporter.info("[ssl-check] TLS 1.0 and TLS 1.1 are not offered. No issues.")

    def _probe_tls_version(self, host: str, port: int,
                           version: ssl.TLSVersion) -> tuple:
        """
        Attempt a handshake locked to a single TLS version.
        Returns (offered: bool, error_message: str | None).
        A True result means the server completed the handshake — protocol is offered.
        """
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version

            sock = socket.create_connection((host, port), timeout=10)
            tls  = ctx.wrap_socket(sock, server_hostname=host)
            tls.close()
            return True, None

        except ssl.SSLError as e:
            return False, str(e)
        except OSError as e:
            return False, str(e)
        except Exception as e:
            return False, str(e)

