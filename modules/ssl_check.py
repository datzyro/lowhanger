"""
modules/ssl_check.py
Module: SslCheckModule

Flags a finding ONLY when testssl.sh reports:
  TLS 1    offered (deprecated)
  TLS 1.1  offered (deprecated)

All other testssl.sh output is ignored.
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

WATCHED_IDS    = {"tls1": "TLS 1.0", "tls1_1": "TLS 1.1"}
OFFERED_MARKER = "offered (deprecated)"


class SslCheckModule(BaseModule):

    def run(self, target: Target, client: HttpClient, reporter: Reporter) -> None:
        host = target.host
        port = target.port or 443
        reporter.info("[ssl-check] Checking deprecated TLS on {}:{}".format(host, port))

        testssl_path = self.template.get("testssl_path", "").strip()
        if not testssl_path:
            testssl_path = shutil.which("testssl.sh") or shutil.which("testssl")

        if testssl_path:
            reporter.info("[ssl-check] Using testssl.sh: {}".format(testssl_path))
            self._run_testssl(host, port, testssl_path, target, reporter)
        else:
            reporter.info("[ssl-check] testssl.sh not found — using Python fallback")
            self._run_python_probe(host, port, target, reporter)

    def _run_testssl(self, host, port, testssl_path, target, reporter):
        json_file = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        json_file.close()

        cmd = [testssl_path, "--protocols",
               "--jsonfile", json_file.name,
               "--color", "0", "--quiet",
               "{}:{}".format(host, port)]

        reporter.debug("  cmd: {}".format(" ".join(cmd)))

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            reporter.warn("[ssl-check] testssl.sh timed out.")
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
            reporter.info("[ssl-check] TLS 1.0 and TLS 1.1 not offered. No issues.")

    def _parse_testssl_json(self, json_path, target, reporter) -> list:
        findings = []
        try:
            with open(json_path) as fh:
                data = json.load(fh)
        except Exception as e:
            reporter.warn("[ssl-check] Could not parse testssl JSON: {}".format(e))
            return findings

        entries = (data if isinstance(data, list)
                   else data.get("scanResult", [{}])[0].get("findings", []))

        for entry in entries:
            entry_id = entry.get("id", "").lower().strip()
            finding  = entry.get("finding", "").lower().strip()

            if entry_id not in WATCHED_IDS:
                continue
            if OFFERED_MARKER not in finding:
                reporter.debug("  {} → '{}' (skipping)".format(entry_id, finding))
                continue

            label = WATCHED_IDS[entry_id]
            findings.append(Finding(
                template_id = self.id,
                name        = "Deprecated Protocol Offered — {}".format(label),
                severity    = "medium",
                target      = target.url,
                affected    = "{}:{}".format(target.host, target.port or 443),
                technique   = "testssl.sh --protocols",
                cause       = "{} offered (deprecated) on {}:{}".format(
                    label, target.host, target.port or 443),
            ))

        return findings

    def _run_python_probe(self, host, port, target, reporter):
        probes = [("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)]
        any_found = False

        for label, version in probes:
            offered, err = self._probe_tls_version(host, port, version)
            if offered:
                any_found = True
                reporter.add_finding(Finding(
                    template_id = self.id,
                    name        = "Deprecated Protocol Offered — {}".format(label),
                    severity    = "medium",
                    target      = target.url,
                    affected    = "{}:{}".format(host, port),
                    technique   = "Direct TLS handshake probe",
                    cause       = "{} handshake completed on {}:{} (protocol offered)".format(
                        label, host, port),
                ))
            else:
                reporter.debug("  {} not offered: {}".format(label, err))

        if not any_found:
            reporter.info("[ssl-check] TLS 1.0 and TLS 1.1 not offered. No issues.")

    def _probe_tls_version(self, host, port, version) -> tuple:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname  = False
            ctx.verify_mode     = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            sock = socket.create_connection((host, port), timeout=10)
            tls  = ctx.wrap_socket(sock, server_hostname=host)
            tls.close()
            return True, None
        except Exception as e:
            return False, str(e)