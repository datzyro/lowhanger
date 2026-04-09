"""
modules/base.py — BaseModule contract.

run() now receives an optional `urls` list:
  - In crawl mode   : pre-crawled, HTML-filtered URL list from the engine
  - In no-crawl mode: [target.url] — only the root URL
  - None            : module should not crawl at all (non-crawl modules
                      like ssl-check and http-redirect ignore this param)
"""

from abc import ABC, abstractmethod
from core.target      import Target
from core.http_client import HttpClient
from core.reporter    import Reporter


class BaseModule(ABC):

    def __init__(self, template: dict):
        self.template    = template
        self.id          = template.get("id",          "unknown")
        self.name        = template.get("name",        "Unknown Check")
        self.severity    = template.get("severity",    "info")
        self.description = template.get("description", "")
        self.tags        = template.get("tags",        [])

    @abstractmethod
    def run(
        self,
        target:   Target,
        client:   HttpClient,
        reporter: Reporter,
        urls:     list = None,
    ) -> None:
        """
        Execute checks against `target`.

        urls : pre-crawled HTML page list supplied by the engine.
               None  → module is non-crawl (ssl-check, http-redirect, host-header).
               []    → no pages found during crawl.
               [..] → HTML pages to run per-page checks on.

        Crawl-based modules MUST use `urls` instead of crawling themselves.
        Non-crawl modules ignore `urls` entirely.
        """
        ...