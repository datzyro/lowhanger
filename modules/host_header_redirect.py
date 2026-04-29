"""
modules/host_header_redirect.py
Module: HostHeaderRedirectModule
"""

import re
import socket
import ssl as _ssl
from modules.base     import BaseModule
from core.target      import Target
from core.http_client import HttpClient
from core.reporter    import Reporter, Finding


def _canary_in_location(location: str, canary: str) -> bool:
    return bool(location) and canary.lower() in location.lower()


def _canary_in_body(body: str, canary: str) -> bool:
    return bool(body) and canary.lower() in body.lower()


def _is_redirect(status_code: int) -> bool:
    return status_code in (301, 302, 303, 307, 308)


def _raw_request(host: str, port: int, raw_bytes: bytes,
                 use_tls: bool = False, timeout: int = 10) -> str:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(raw_bytes)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        sock.close()
        return b"".join(chunks).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _parse_raw_response(raw: str) -> tuple:
    if not raw:
        return 0, {}, ""
    lines = raw.split("\r\n")
    status = 0
    try:
        status = int(lines[0].split(" ", 2)[1])
    except (IndexError, ValueError):
        pass
    headers    = {}
    body_start = 0
    for i, line in enumerate(lines[1:], 1):
        if line == "":
            body_start = i + 1
            break
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    body = "\r\n".join(lines[body_start:])
    return status, headers, body


class HostHeaderRedirectModule(BaseModule):

    def run(self, target: Target, client: HttpClient, reporter: Reporter, urls: list = None) -> None:
        canary     = self.template.get("canary", "evil.lowhanger.internal")
        techniques = set(self.template.get("techniques", []))
        check_body = self.template.get("detection", {}).get("body_reflection", True)

        reporter.info("[host-header-redirect] Scanning {} (canary={})".format(
            target.url, canary))

        dispatch = {
            "direct_host":           self._tech_direct_host,
            "x_forwarded_host":      self._tech_x_forwarded_host,
            "x_host":                self._tech_x_host,
            "x_forwarded_server":    self._tech_x_forwarded_server,
            "x_http_host_override":  self._tech_x_http_host_override,
            "forwarded_header":      self._tech_forwarded_header,
            "host_port_confusion":   self._tech_host_port_confusion,
            "double_host":           self._tech_double_host,
            "absolute_uri":          self._tech_absolute_uri,
            "host_with_path":        self._tech_host_with_path,
            "host_subdomain_bypass": self._tech_host_subdomain_bypass,
            "https_redirect_abuse":  self._tech_https_redirect_abuse,
        }

        for tech_id, fn in dispatch.items():
            if tech_id not in techniques:
                continue
            reporter.debug("  trying: {}".format(tech_id))
            try:
                fn(target, canary, client, reporter, check_body)
            except (ConnectionError, TimeoutError) as e:
                reporter.warn("  {} → connection error: {}".format(tech_id, e))
            except Exception as e:
                reporter.warn("  {} → error: {}".format(tech_id, e))

    # ── technique helpers ────────────────────────────────────────────── #

    def _check(self, resp, canary, target, reporter, technique, check_body):
        location = resp.location or ""
        if _is_redirect(resp.status_code) and _canary_in_location(location, canary):
            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "Host Header Injection — Open Redirect",
                severity    = self.severity,
                target      = target.url,
                affected    = target.url,
                technique   = technique,
                cause       = "HTTP {} → Location: {}".format(resp.status_code, location),
            ))
        elif check_body and _canary_in_body(resp.text, canary):
            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "Host Header Injection — Host Reflection in Response",
                severity    = "low",
                target      = target.url,
                affected    = target.url,
                technique   = technique,
                cause       = "HTTP {} — canary '{}' reflected in response body".format(
                    resp.status_code, canary),
            ))

    def _check_raw(self, status, headers, body, canary, target, reporter, technique, check_body):
        location = headers.get("location", "")
        if _is_redirect(status) and _canary_in_location(location, canary):
            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "Host Header Injection — Open Redirect",
                severity    = self.severity,
                target      = target.url,
                affected    = target.url,
                technique   = technique,
                cause       = "HTTP {} → Location: {}".format(status, location),
            ))
        elif check_body and _canary_in_body(body, canary):
            reporter.add_finding(Finding(
                template_id = self.id,
                name        = "Host Header Injection — Host Reflection in Response",
                severity    = "low",
                target      = target.url,
                affected    = target.url,
                technique   = technique,
                cause       = "HTTP {} — canary reflected in body".format(status),
            ))

    # ── techniques ───────────────────────────────────────────────────── #

    def _tech_direct_host(self, target, canary, client, reporter, check_body):
        resp = client.get(target.url, headers={"Host": canary})
        self._check(resp, canary, target, reporter, "Host: {}".format(canary), check_body)

    def _tech_x_forwarded_host(self, target, canary, client, reporter, check_body):
        resp = client.get(target.url, headers={"X-Forwarded-Host": canary})
        self._check(resp, canary, target, reporter, "X-Forwarded-Host: {}".format(canary), check_body)

    def _tech_x_host(self, target, canary, client, reporter, check_body):
        resp = client.get(target.url, headers={"X-Host": canary})
        self._check(resp, canary, target, reporter, "X-Host: {}".format(canary), check_body)

    def _tech_x_forwarded_server(self, target, canary, client, reporter, check_body):
        resp = client.get(target.url, headers={"X-Forwarded-Server": canary})
        self._check(resp, canary, target, reporter, "X-Forwarded-Server: {}".format(canary), check_body)

    def _tech_x_http_host_override(self, target, canary, client, reporter, check_body):
        resp = client.get(target.url, headers={"X-HTTP-Host-Override": canary})
        self._check(resp, canary, target, reporter, "X-HTTP-Host-Override: {}".format(canary), check_body)

    def _tech_forwarded_header(self, target, canary, client, reporter, check_body):
        resp = client.get(target.url, headers={"Forwarded": "host={}".format(canary)})
        self._check(resp, canary, target, reporter, "Forwarded: host={}".format(canary), check_body)

    def _tech_host_port_confusion(self, target, canary, client, reporter, check_body):
        val  = "{}:80".format(canary)
        resp = client.get(target.url, headers={"Host": val})
        self._check(resp, canary, target, reporter, "Host: {} (port confusion)".format(val), check_body)

    def _tech_double_host(self, target, canary, client, reporter, check_body):
        host = target.host
        port = target.port or (443 if target.scheme == "https" else 80)
        tls  = target.scheme == "https"
        path = target.path or "/"
        raw  = ("GET {} HTTP/1.1\r\nHost: {}\r\nHost: {}\r\n"
                "Connection: close\r\nUser-Agent: lowhanger\r\n\r\n").format(
                    path, host, canary).encode()
        resp_str             = _raw_request(host, port, raw, use_tls=tls, timeout=client.timeout)
        status, headers, body = _parse_raw_response(resp_str)
        self._check_raw(status, headers, body, canary, target, reporter,
                        "Duplicate Host headers (Host: {} + Host: {})".format(host, canary),
                        check_body)

    def _tech_absolute_uri(self, target, canary, client, reporter, check_body):
        host = target.host
        port = target.port or (443 if target.scheme == "https" else 80)
        tls  = target.scheme == "https"
        path = target.path or "/"
        raw  = ("GET http://{}{} HTTP/1.1\r\nHost: {}\r\n"
                "Connection: close\r\nUser-Agent: lowhanger\r\n\r\n").format(
                    canary, path, host).encode()
        resp_str              = _raw_request(host, port, raw, use_tls=tls, timeout=client.timeout)
        status, headers, body = _parse_raw_response(resp_str)
        self._check_raw(status, headers, body, canary, target, reporter,
                        "Absolute-URI: GET http://{}{} HTTP/1.1".format(canary, path),
                        check_body)

    def _tech_host_with_path(self, target, canary, client, reporter, check_body):
        val  = "{}/bypass".format(canary)
        resp = client.get(target.url, headers={"Host": val})
        self._check(resp, canary, target, reporter, "Host: {} (path confusion)".format(val), check_body)

    def _tech_host_subdomain_bypass(self, target, canary, client, reporter, check_body):
        crafted = "{}.{}".format(target.host, canary)
        resp    = client.get(target.url, headers={"Host": crafted})
        self._check(resp, canary, target, reporter,
                    "Host: {} (suffix bypass)".format(crafted), check_body)
# change few funcs to test the raw request/response parsing and detection logic 
    def _tech_https_redirect_abuse(self, target, canary, client, reporter, check_body):
        http_url = target.http_url
        variants = [
            (canary,
             "HTTP→HTTPS redirect abuse | Host: {}".format(canary)),
            ("{}:80".format(canary),
             "HTTP→HTTPS redirect abuse | Host: {}:80".format(canary)),
            ("{}@{}".format(target.host, canary),
             "HTTP→HTTPS redirect abuse | Host: {}@{}".format(target.host, canary)),
        ]
        for host_val, technique in variants:
            reporter.debug("    variant: {}".format(host_val))
            try:
                resp     = client.get(http_url, headers={"Host": host_val})
                location = resp.location or ""
                if _is_redirect(resp.status_code) and _canary_in_location(location, canary):
                    reporter.add_finding(Finding(
                        template_id = self.id,
                        name        = "Host Header Injection — Open Redirect",
                        severity    = self.severity,
                        target      = target.url,
                        affected    = http_url,
                        technique   = technique,
                        cause       = "HTTP {} → Location: {}".format(resp.status_code, location),
                    ))
                elif check_body and _canary_in_body(resp.text, canary):
                    reporter.add_finding(Finding(
                        template_id = self.id,
                        name        = "Host Header Injection — Host Reflection in Response",
                        severity    = "low",
                        target      = target.url,
                        affected    = http_url,
                        technique   = technique,
                        cause       = "HTTP {} — canary '{}' reflected in body".format(
                            resp.status_code, canary),
                    ))
            except (ConnectionError, TimeoutError) as e:
                reporter.debug("    variant skipped: {}".format(e))