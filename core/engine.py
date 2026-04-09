"""
core/engine.py — Template loader and scan orchestrator.

Two scan modes
──────────────
  crawl mode (default)
    1. Crawl the target once using katana / built-in BFS
    2. Filter crawled URLs to HTML-only pages (page_filter)
    3. Pass the filtered URL list to every crawl-based module
       so each module checks every discovered page — no repeated crawling
    4. Non-crawl modules (ssl-check, http-redirect, host-header-redirect)
       receive urls=None and handle their own requests

  no-crawl mode (--no-crawl)
    1. Skip crawling entirely
    2. Pass urls=[target.url] to every crawl-based module
       (they run their checks on the root URL only — fast surface scan)
    3. Non-crawl modules behave identically to crawl mode

Module categorisation
─────────────────────
  CRAWL_BASED : security-headers, clickjacking, cors, version-disclosure
  STANDALONE  : ssl-check, http-redirect, host-header-redirect
"""

import os
import importlib
import re
import yaml

from core.target      import Target
from core.http_client import HttpClient
from core.reporter    import Reporter
from core.crawler     import crawl
from core.page_filter import filter_html_urls


TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
MODULES_PKG   = "modules"

# Modules that consume a URL list — the engine manages crawling for these
CRAWL_BASED_TEMPLATES = {
    "security-headers",
    "clickjacking",
    "cors",
    "version-disclosure",
}

# Execution order
_PRIORITY = {
    "ssl-check":             1,
    "http-redirect":         2,
    "version-disclosure":    3,
    "security-headers":      4,
    "clickjacking":          5,
    "cors":                  6,
    "host-header-redirect":  7,
}


class Engine:

    def __init__(
        self,
        reporter:         Reporter,
        template_filter:  list = None,
        crawl_mode:       bool = True,    # False = no-crawl / surface scan
        crawl_depth:      int  = None,    # override per-template crawl_depth
        timeout:          int  = 10,
        follow_redirects: bool = False,
        proxies:          dict = None,
    ):
        self.reporter         = reporter
        self.template_filter  = template_filter
        self.crawl_mode       = crawl_mode
        self.crawl_depth      = crawl_depth
        self.timeout          = timeout
        self.follow_redirects = follow_redirects
        self.proxies          = proxies or {}

        self._templates = self._load_templates()
        self._client    = HttpClient(
            timeout=timeout,
            follow_redirects=follow_redirects,
            proxies=proxies,
        )

    # ──────────────────────────────────────────────────────────────────── #
    # Public scan entry point                                              #
    # ──────────────────────────────────────────────────────────────────── #

    def scan(self, targets: list) -> None:
        if not self._templates:
            self.reporter.error("No templates loaded — nothing to run.")
            return

        mode_label = "crawl" if self.crawl_mode else "no-crawl (surface)"
        self.reporter.info("Mode: {}  |  {} template(s)  |  {} target(s)".format(
            mode_label, len(self._templates), len(targets)))

        for idx, target in enumerate(targets, 1):
            self.reporter.info("[{}/{}] {}".format(idx, len(targets), target.url))
            self._scan_target(target)

    def _scan_target(self, target: Target) -> None:
        # ── Step 1: Determine URL list for crawl-based modules ─────── #
        html_urls = self._get_html_urls(target)

        # ── Step 2: Run each template ──────────────────────────────── #
        for tmpl in self._templates:
            module = self._instantiate_module(tmpl)
            if module is None:
                continue

            tid = tmpl.get("id", "")
            self.reporter.info("  running: {}".format(tid))

            # Crawl-based modules get the HTML page list
            # Standalone modules get urls=None
            if tid in CRAWL_BASED_TEMPLATES:
                urls_arg = html_urls
            else:
                urls_arg = None

            try:
                module.run(target, self._client, self.reporter, urls=urls_arg)
            except Exception as e:
                self.reporter.error("Module {} crashed on {}: {}".format(
                    tid, target.url, e))

    # ──────────────────────────────────────────────────────────────────── #
    # Crawl + filter                                                        #
    # ──────────────────────────────────────────────────────────────────── #

    def _get_html_urls(self, target: Target) -> list:
        """
        Crawl mode  : crawl once, filter to HTML pages, return the list.
        No-crawl    : return [target.url] — root only.
        """
        if not self.crawl_mode:
            self.reporter.info("  [no-crawl] skipping crawl — checking root URL only")
            return [target.url]

        # Determine crawl depth — use CLI override or fall back to first
        # crawl-based template's crawl_depth setting (they're usually the same)
        depth = self.crawl_depth
        if depth is None:
            for tmpl in self._templates:
                if tmpl.get("id") in CRAWL_BASED_TEMPLATES:
                    depth = tmpl.get("crawl_depth", 3)
                    break
            if depth is None:
                depth = 3

        proxy = list(self.proxies.values())[0] if self.proxies else None

        self.reporter.info("  [crawl] depth={} — starting...".format(depth))
        all_urls = crawl(
            target,
            depth   = depth,
            timeout = self.timeout,
            proxy   = proxy,
            verbose = self.reporter.verbose,
        )
        self.reporter.info("  [crawl] {} raw URL(s) found".format(len(all_urls)))

        # Filter to HTML pages only
        html_urls = filter_html_urls(all_urls, self._client, self.reporter)
        self.reporter.info("  [crawl] {} HTML page(s) after filtering".format(len(html_urls)))

        return html_urls

    # ──────────────────────────────────────────────────────────────────── #
    # Template loading                                                     #
    # ──────────────────────────────────────────────────────────────────── #

    def _load_templates(self) -> list:
        templates = []
        if not os.path.isdir(TEMPLATES_DIR):
            self.reporter.error("Templates directory not found: {}".format(TEMPLATES_DIR))
            return templates

        yaml_files = sorted(
            [f for f in os.listdir(TEMPLATES_DIR) if f.endswith((".yaml", ".yml"))],
            key=lambda f: _PRIORITY.get(f.replace(".yaml","").replace(".yml",""), 99)
        )

        for fname in yaml_files:
            fpath = os.path.join(TEMPLATES_DIR, fname)
            try:
                with open(fpath) as fh:
                    tmpl = yaml.safe_load(fh)
            except yaml.YAMLError as e:
                self.reporter.warn("Bad YAML in {}: {}".format(fname, e))
                continue

            if not tmpl or "id" not in tmpl:
                self.reporter.warn("Template {} missing 'id' — skipping".format(fname))
                continue

            if self.template_filter and "all" not in self.template_filter:
                if tmpl["id"] not in self.template_filter:
                    continue

            templates.append(tmpl)
            self.reporter.debug("Loaded template: {}".format(tmpl["id"]))

        return templates

    # ──────────────────────────────────────────────────────────────────── #
    # Module instantiation                                                 #
    # ──────────────────────────────────────────────────────────────────── #

    def _instantiate_module(self, template: dict):
        class_name = template.get("module")
        if not class_name:
            self.reporter.warn("Template {} has no 'module' field".format(template.get("id")))
            return None

        module_file = _camel_to_snake(class_name).replace("_module", "")
        module_path = "{}.{}".format(MODULES_PKG, module_file)

        try:
            mod = importlib.import_module(module_path)
        except ModuleNotFoundError:
            self.reporter.error("Cannot import '{}' (template: {})".format(
                module_path, template.get("id")))
            return None

        cls = getattr(mod, class_name, None)
        if cls is None:
            self.reporter.error("Class '{}' not found in {}".format(class_name, module_path))
            return None

        return cls(template)


def _camel_to_snake(name: str) -> str:
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()