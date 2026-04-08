"""
core/target.py — Target model and normalization.

Accepts bare domains, http://, and https:// inputs.
Normalizes into a consistent Target object used across all modules.
"""

from urllib.parse import urlparse


class Target:
    """
    Represents a single scan target.

    Attributes:
        raw        : original input string
        scheme     : "http" | "https"
        host       : hostname only (no port, no path)
        port       : int or None
        path       : URL path, defaults to "/"
        origin     : scheme://host[:port]
        url        : full normalized URL
    """

    def __init__(self, raw: str):
        self.raw = raw.strip()
        self._parse()

    def _parse(self):
        raw = self.raw
        if not raw.startswith("http://") and not raw.startswith("https://"):
            raw = "https://" + raw

        parsed = urlparse(raw)
        self.scheme = parsed.scheme or "https"
        self.host   = parsed.hostname or ""
        self.port   = parsed.port
        self.path   = parsed.path or "/"

        if self.port:
            self.origin = f"{self.scheme}://{self.host}:{self.port}"
        else:
            self.origin = f"{self.scheme}://{self.host}"

        self.url = self.origin + self.path

    @property
    def http_url(self) -> str:
        if self.port:
            return f"http://{self.host}:{self.port}{self.path}"
        return f"http://{self.host}{self.path}"

    @property
    def https_url(self) -> str:
        if self.port:
            return f"https://{self.host}:{self.port}{self.path}"
        return f"https://{self.host}{self.path}"

    @property
    def host_header(self) -> str:
        if self.port and self.port not in (80, 443):
            return f"{self.host}:{self.port}"
        return self.host

    def __repr__(self):
        return f"<Target {self.url}>"

    def __str__(self):
        return self.url


def load_targets(paths: list, urls: list) -> list:
    seen    = set()
    targets = []
    raw_list = list(urls or [])

    for fpath in (paths or []):
        try:
            with open(fpath) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        raw_list.append(line)
        except FileNotFoundError:
            raise FileNotFoundError(f"Target file not found: {fpath}")

    for raw in raw_list:
        if raw not in seen:
            seen.add(raw)
            targets.append(Target(raw))

    return targets
