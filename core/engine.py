"""
core/engine.py — Template loader and scan orchestrator.

Workflow:
  1. Discover YAML templates from templates/ directory
  2. For each template, import the matching Python module class
  3. For each target, instantiate the module and call module.run()
"""

import os
import importlib
import re
import yaml
from core.target      import Target
from core.http_client import HttpClient
from core.reporter    import Reporter


TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
MODULES_PKG   = "modules"


class Engine:

    def __init__(
        self,
        reporter:         Reporter,
        template_filter:  list = None,
        timeout:          int  = 10,
        follow_redirects: bool = False,
        proxies:          dict = None,
    ):
        self.reporter         = reporter
        self.template_filter  = template_filter
        self.timeout          = timeout
        self.follow_redirects = follow_redirects
        self.proxies          = proxies or {}

        self._templates = self._load_templates()
        self._client    = HttpClient(
            timeout=timeout,
            follow_redirects=follow_redirects,
            proxies=proxies,
        )

    def scan(self, targets: list) -> None:
        if not self._templates:
            self.reporter.error("No templates loaded — nothing to run.")
            return

        total_targets   = len(targets)
        total_templates = len(self._templates)

        self.reporter.info(
            "Loaded {} template(s), scanning {} target(s)".format(
                total_templates, total_targets)
        )

        for idx, target in enumerate(targets, 1):
            self.reporter.info(
                "[{}/{}] {}".format(idx, total_targets, target.url)
            )
            for tmpl in self._templates:
                module = self._instantiate_module(tmpl)
                if module is None:
                    continue
                self.reporter.info(
                    "  running: {} [{}]".format(tmpl.get("id"), tmpl.get("severity", "?"))
                )
                try:
                    module.run(target, self._client, self.reporter)
                except Exception as e:
                    self.reporter.error(
                        "Module {} crashed on {}: {}".format(
                            tmpl.get("id"), target.url, e)
                    )

    # ──────────────────────────────────────────────────────────────────── #
    # Template loading                                                     #
    # ──────────────────────────────────────────────────────────────────── #

    def _load_templates(self) -> list:
        templates = []
        if not os.path.isdir(TEMPLATES_DIR):
            self.reporter.error("Templates directory not found: {}".format(TEMPLATES_DIR))
            return templates

        # Load order: fast/non-crawl checks first, crawl-heavy last
        _priority = {
            "ssl-check":             1,
            "http-redirect":         2,
            "version-disclosure":    3,
            "security-headers":      4,
            "clickjacking":          5,
            "cors":                  6,
            "host-header-redirect":  7,
        }

        yaml_files = sorted(
            [f for f in os.listdir(TEMPLATES_DIR) if f.endswith((".yaml", ".yml"))],
            key=lambda f: _priority.get(f.replace(".yaml", "").replace(".yml", ""), 99)
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
                self.reporter.warn("Template {} missing 'id' field — skipping".format(fname))
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
        class_name  = template.get("module")
        if not class_name:
            self.reporter.warn(
                "Template {} has no 'module' field — skipping".format(template.get("id")))
            return None

        module_file = _camel_to_snake(class_name).replace("_module", "")
        module_path = "{}.{}".format(MODULES_PKG, module_file)

        try:
            mod = importlib.import_module(module_path)
        except ModuleNotFoundError:
            self.reporter.error(
                "Cannot import module '{}' (template: {})".format(
                    module_path, template.get("id")))
            return None

        cls = getattr(mod, class_name, None)
        if cls is None:
            self.reporter.error(
                "Class '{}' not found in {}".format(class_name, module_path))
            return None

        return cls(template)


def _camel_to_snake(name: str) -> str:
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()
