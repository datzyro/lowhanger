"""
core/http_client.py — Shared HTTP client with sane pentest defaults.

- Follows redirects manually so we can inspect each hop
- Does NOT verify SSL by default (pentest context)
- Configurable timeout and User-Agent
- Returns a lightweight Response wrapper with extra metadata
"""

import socket
import time
import urllib3
import requests
from urllib.parse import urlparse

# Suppress InsecureRequestWarning — intentional in a pentest tool
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


DEFAULT_TIMEOUT    = 10          # seconds per request
DEFAULT_UA         = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
MAX_REDIRECTS      = 10


class ProbeResponse:
    """
    Thin wrapper around requests.Response that adds convenience fields
    useful for vulnerability detection.
    """

    def __init__(self, raw: requests.Response, elapsed: float, redirect_chain: list):
        self.raw            = raw
        self.status_code    = raw.status_code
        self.headers        = raw.headers
        self.text           = raw.text
        self.url            = raw.url          # final URL after redirects (if followed)
        self.elapsed        = elapsed          # seconds
        self.redirect_chain = redirect_chain   # list of (status_code, location) tuples

    @property
    def location(self) -> str | None:
        return self.headers.get("Location") or self.headers.get("location")

    def __repr__(self):
        return f"<ProbeResponse {self.status_code} {self.url}>"


class HttpClient:
    """
    Reusable HTTP client for all lowhanger modules.

    Parameters
    ----------
    timeout       : per-request timeout in seconds
    user_agent    : UA string
    verify_ssl    : whether to verify TLS certificates
    follow_redirects : if True, requests follows redirects automatically.
                       if False (default for most checks), we get the raw 3xx.
    proxies       : optional dict passed straight to requests
    """

    def __init__(
        self,
        timeout:          int  = DEFAULT_TIMEOUT,
        user_agent:       str  = DEFAULT_UA,
        verify_ssl:       bool = False,
        follow_redirects: bool = False,
        proxies:          dict = None,
    ):
        self.timeout          = timeout
        self.user_agent       = user_agent
        self.verify_ssl       = verify_ssl
        self.follow_redirects = follow_redirects
        self.proxies          = proxies or {}

        self._session = requests.Session()
        self._session.verify  = self.verify_ssl
        self._session.proxies = self.proxies
        self._session.headers.update({"User-Agent": self.user_agent})

        # Disable built-in redirect following — we handle it ourselves
        self._session.max_redirects = MAX_REDIRECTS

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def get(
        self,
        url:     str,
        headers: dict = None,
        params:  dict = None,
    ) -> ProbeResponse:
        return self._request("GET", url, headers=headers, params=params)

    def head(
        self,
        url:     str,
        headers: dict = None,
    ) -> ProbeResponse:
        return self._request("HEAD", url, headers=headers)

    def post(
        self,
        url:     str,
        headers: dict = None,
        data:    dict = None,
        json:    dict = None,
    ) -> ProbeResponse:
        return self._request("POST", url, headers=headers, data=data, json=json)

    # ------------------------------------------------------------------ #
    # Internal                                                             #
    # ------------------------------------------------------------------ #

    def _request(self, method: str, url: str, **kwargs) -> ProbeResponse:
        start          = time.monotonic()
        redirect_chain = []
        current_url    = url
        extra_headers  = kwargs.pop("headers", None) or {}

        for _ in range(MAX_REDIRECTS):
            merged_headers = dict(self._session.headers)
            merged_headers.update(extra_headers)

            try:
                resp = self._session.request(
                    method,
                    current_url,
                    headers=merged_headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                    **kwargs,
                )
            except requests.exceptions.SSLError as e:
                raise ConnectionError(f"SSL error for {current_url}: {e}")
            except requests.exceptions.ConnectionError as e:
                raise ConnectionError(f"Connection failed for {current_url}: {e}")
            except requests.exceptions.Timeout:
                raise TimeoutError(f"Timeout after {self.timeout}s for {current_url}")

            elapsed = time.monotonic() - start

            # Record hop
            loc = resp.headers.get("Location") or resp.headers.get("location") or ""
            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                redirect_chain.append((resp.status_code, loc))

            # Stop if we don't want to follow or there's nowhere to go
            if not self.follow_redirects or not loc:
                return ProbeResponse(resp, elapsed, redirect_chain)

            # Resolve relative redirects
            if loc.startswith("/"):
                parsed = urlparse(current_url)
                current_url = f"{parsed.scheme}://{parsed.netloc}{loc}"
            elif not loc.startswith("http"):
                parsed = urlparse(current_url)
                current_url = f"{parsed.scheme}://{parsed.netloc}/{loc}"
            else:
                current_url = loc

            method = "GET"   # POST → redirect → GET (standard browser behaviour)

        # Fell through max redirects — return last response
        return ProbeResponse(resp, elapsed, redirect_chain)
