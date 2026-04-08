"""
modules/base.py — BaseModule contract that every lowhanger module must satisfy.

A module maps 1:1 to a YAML template. The engine:
  1. Loads the YAML template
  2. Instantiates the matching Python module class
  3. Calls module.run(target, client, reporter)

Modules are discovered by template `module` field matching the class name
(case-insensitive) inside the modules/ package.
"""

from abc import ABC, abstractmethod
from core.target   import Target
from core.http_client import HttpClient
from core.reporter import Reporter


class BaseModule(ABC):
    """
    Abstract base for all lowhanger check modules.

    Subclasses MUST implement `run()`.
    Template metadata is injected by the engine at instantiation.
    """

    def __init__(self, template: dict):
        """
        Parameters
        ----------
        template : parsed YAML dict for this module
        """
        self.template    = template
        self.id          = template.get("id",          "unknown")
        self.name        = template.get("name",        "Unknown Check")
        self.severity    = template.get("severity",    "info")
        self.description = template.get("description", "")
        self.remediation = template.get("remediation", "")
        self.tags        = template.get("tags",        [])

    @abstractmethod
    def run(
        self,
        target:   Target,
        client:   HttpClient,
        reporter: Reporter,
    ) -> None:
        """
        Execute all checks for this module against `target`.

        Findings are emitted by calling reporter.add_finding(Finding(...)).
        Errors/warnings via reporter.error() / reporter.warn().
        Verbose progress via reporter.info() / reporter.debug().
        """
        ...

    # ------------------------------------------------------------------ #
    # Helpers available to all subclasses                                 #
    # ------------------------------------------------------------------ #

    def _finding_kwargs(self, technique: str, evidence: str, detail: str = "") -> dict:
        """Build the common kwargs for a Finding."""
        return dict(
            template_id  = self.id,
            name         = self.name,
            severity     = self.severity,
            technique    = technique,
            evidence     = evidence,
            detail       = detail,
            remediation  = self.remediation,
        )
