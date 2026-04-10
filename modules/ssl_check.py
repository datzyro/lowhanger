"""
modules/ssl_check.py
Module: SslCheckModule

Streams testssl.sh stdout line by line and kills the process the moment
both TLS 1.0 and TLS 1.1 result lines have been seen — no waiting for
cipher checks, certificate checks, or anything else.

If either or both are "offered (deprecated)", one single combined finding
is emitted. If neither is offered, no finding is produced.

No JSON file, no blocking subprocess.run() — process is killed immediately
after the two lines we care about appear in the output.
"""

import re
import shutil
import socket
import ssl
import subprocess
from modules.base     import BaseModule
from core.target      import Target
from core.http_client import HttpClient
from core.reporter    import Reporter, Finding


# Matches testssl stdout lines like:
#   " TLS 1      offered (deprecated)"
#   " TLS 1.1    not offered (OK)"
#   " TLS 1      not offered, but . . ."
_TLS1_RE   = re.compile(r'\bTLS\s+1\s+(offered[^\n]*|not offered[^\n]*)', re.IGNORECASE)
_TLS11_RE  = re.compile(r'\bTLS\s+1\.1\s+(offered[^\n]*|not offered[^\n]*)', re.IGNORECASE)
_OFFERED_RE = re.compile(r'\boffered\s*\(deprecated\)', re.IGNORECASE)


class SslCheckModule(BaseModule):

    def run(self, target: Target, client: HttpClient,
            reporter: Reporter, urls: list = None) -> None:
        host = target.host
        port = target.port or 443
        reporter.info("[ssl-check] Checking deprecated TLS on {}:{}".format(host, port))

        testssl_path = self.template.get("testssl_path", "").strip()
        if not testssl_path:
            testssl_path = shutil.which("testssl.sh") or shutil.which("testssl")

        if testssl_path:
            reporter.info("[ssl-check] Using testssl.sh — will kill after TLS 1/1.1 lines")
            self._run_testssl_streaming(host, port, testssl_path, target, reporter)
        else:
            reporter.info("[ssl-check] testssl.sh not found — using Python fallback")
            self._run_python_probe(host, port, target, reporter)

    # ──────────────────────────────────────────────────────────────────── #
    # testssl.sh — streaming stdout, kill on completion                   #
    # ──────────────────────────────────────────────────────────────────── #

    def _run_testssl_streaming(self, host, port, testssl_path, target, reporter):
        """
        Spawn testssl.sh, read stdout line by line.
        As soon as both TLS 1 and TLS 1.1 result lines have appeared,
        kill the process — we have everything we need.
        """
        cmd = [
            testssl_path,
            "--protocols",   # only protocol checks — already limits scope
            "--color", "0",  # no ANSI codes in output
            "--quiet",
            "{}:{}".format(host, port),
        ]
        reporter.debug("  cmd: {}".format(" ".join(cmd)))

        tls1_offered   = None   # True/False/None = not seen yet
        tls11_offered  = None

        proc = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,   # line-buffered
            )

            for line in proc.stdout:
                reporter.debug("  testssl: {}".format(line.rstrip()))

                # Check for TLS 1 line (must NOT match TLS 1.1)
                if tls1_offered is None and _TLS1_RE.search(line) and "1.1" not in line:
                    tls1_offered = bool(_OFFERED_RE.search(line))
                    reporter.debug("  TLS 1.0 → {}".format(
                        "OFFERED" if tls1_offered else "not offered"))

                # Check for TLS 1.1 line
                if tls11_offered is None and _TLS11_RE.search(line):
                    tls11_offered = bool(_OFFERED_RE.search(line))
                    reporter.debug("  TLS 1.1 → {}".format(
                        "OFFERED" if tls11_offered else "not offered"))

                # Both seen — kill immediately, we're done
                if tls1_offered is not None and tls11_offered is not None:
                    reporter.debug("  Both results collected — killing testssl.sh")
                    proc.kill()
                    break

        except Exception as e:
            reporter.error("[ssl-check] testssl.sh error: {}".format(e))
            return
        finally:
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                except Exception:
                    pass
            if proc:
                try:
                    proc.stdout.close()
                except Exception:
                    pass

        # Emit finding
        self._emit_finding(tls1_offered, tls11_offered, host, port, target, reporter,
                           technique="testssl.sh --protocols (stdout streaming)")

    # ──────────────────────────────────────────────────────────────────── #
    # Python fallback                                                      #
    # ──────────────────────────────────────────────────────────────────── #

    def _run_python_probe(self, host, port, target, reporter):
        probes = [
            ("TLS 1.0", ssl.TLSVersion.TLSv1),
            ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
        ]
        results = {}
        for label, version in probes:
            offered, err = self._probe_tls_version(host, port, version)
            results[label] = offered
            reporter.debug("  {} → {}".format(label, "OFFERED" if offered else "not offered ({})".format(err)))

        self._emit_finding(
            results.get("TLS 1.0"), results.get("TLS 1.1"),
            host, port, target, reporter,
            technique="Direct TLS handshake probe",
        )

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

    # ──────────────────────────────────────────────────────────────────── #
    # Single combined finding                                              #
    # ──────────────────────────────────────────────────────────────────── #

    def _emit_finding(self, tls1_offered, tls11_offered, host, port,
                      target, reporter, technique):
        """
        Emit ONE finding if any deprecated protocol is offered.
        Lists exactly which protocols were found.
        """
        offered = []
        if tls1_offered:
            offered.append("TLS 1.0")
        if tls11_offered:
            offered.append("TLS 1.1")

        if not offered:
            reporter.info("[ssl-check] TLS 1.0 and TLS 1.1 not offered. No issues.")
            return

        reporter.add_finding(Finding(
            template_id = self.id,
            name        = "Deprecated TLS Protocol(s) Offered",
            severity    = "medium",
            target      = target.url,
            affected    = "{}:{}".format(host, port),
            technique   = technique,
            cause       = "{} offered (deprecated) on {}:{}".format(
                " and ".join(offered), host, port),
        ))