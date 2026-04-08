"""
core/reporter.py — Output formatting and result aggregation.

Supports: pretty terminal output (coloured), plain text, JSON.
"""

import json
import sys
from datetime import datetime
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)


# Severity colours
SEVERITY_COLOUR = {
    "info":     Fore.CYAN,
    "low":      Fore.GREEN,
    "medium":   Fore.YELLOW,
    "high":     Fore.RED,
    "critical": Fore.MAGENTA,
}


class Finding:
    """
    A single vulnerability finding produced by a module.
    """

    def __init__(
        self,
        template_id:  str,
        name:         str,
        severity:     str,
        target:       str,
        technique:    str,
        evidence:     str,
        detail:       str  = "",
        remediation:  str  = "",
    ):
        self.template_id  = template_id
        self.name         = name
        self.severity     = severity.lower()
        self.target       = target
        self.technique    = technique
        self.evidence     = evidence
        self.detail       = detail
        self.remediation  = remediation
        self.timestamp    = datetime.utcnow().isoformat() + "Z"

    def to_dict(self) -> dict:
        return {
            "template_id":  self.template_id,
            "name":         self.name,
            "severity":     self.severity,
            "target":       self.target,
            "technique":    self.technique,
            "evidence":     self.evidence,
            "detail":       self.detail,
            "remediation":  self.remediation,
            "timestamp":    self.timestamp,
        }


class Reporter:

    def __init__(self, verbose: bool = False, output_file: str = None, fmt: str = "pretty"):
        self.verbose     = verbose
        self.output_file = output_file
        self.fmt         = fmt          # "pretty" | "plain" | "json"
        self.findings    = []
        self._errors     = []

    # ------------------------------------------------------------------ #
    # Public API used by modules / engine                                 #
    # ------------------------------------------------------------------ #

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        self._print_finding(finding)

    def info(self, msg: str):
        if self.verbose:
            print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}")

    def debug(self, msg: str):
        if self.verbose:
            print(f"{Fore.WHITE}[~]{Style.RESET_ALL} {msg}")

    def warn(self, msg: str):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}", file=sys.stderr)

    def error(self, msg: str):
        self._errors.append(msg)
        print(f"{Fore.RED}[E]{Style.RESET_ALL} {msg}", file=sys.stderr)

    def print_banner(self):
        banner = f"""{Fore.RED}
  ██╗      ██████╗ ██╗    ██╗██╗  ██╗ █████╗ ███╗   ██╗ ██████╗ ███████╗██████╗
  ██║     ██╔═══██╗██║    ██║██║  ██║██╔══██╗████╗  ██║██╔════╝ ██╔════╝██╔══██╗
  ██║     ██║   ██║██║ █╗ ██║███████║███████║██╔██╗ ██║██║  ███╗█████╗  ██████╔╝
  ██║     ██║   ██║██║███╗██║██╔══██║██╔══██║██║╚██╗██║██║   ██║██╔══╝  ██╔══██╗
  ███████╗╚██████╔╝╚███╔███╔╝██║  ██║██║  ██║██║ ╚████║╚██████╔╝███████╗██║  ██║
  ╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}{Fore.WHITE}  pick the fruit before they patch it  {Style.RESET_ALL}
"""
        print(banner)

    def print_summary(self):
        total = len(self.findings)
        by_sev = {}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

        print(f"\n{Style.BRIGHT}{'─'*60}")
        print(f"  SCAN COMPLETE — {total} finding(s)")
        for sev in ("critical", "high", "medium", "low", "info"):
            count = by_sev.get(sev, 0)
            if count:
                col = SEVERITY_COLOUR.get(sev, "")
                print(f"  {col}{sev.upper():10s}{Style.RESET_ALL} {count}")
        print(f"{'─'*60}{Style.RESET_ALL}\n")

        if self.output_file:
            self._write_output()

    # ------------------------------------------------------------------ #
    # Internal                                                             #
    # ------------------------------------------------------------------ #

    def _print_finding(self, f: Finding):
        col   = SEVERITY_COLOUR.get(f.severity, Fore.WHITE)
        label = f"[{f.severity.upper()}]"
        print(
            f"\n{col}{label}{Style.RESET_ALL} "
            f"{Style.BRIGHT}{f.name}{Style.RESET_ALL}"
        )
        print(f"  {'Target':12s}: {f.target}")
        print(f"  {'Technique':12s}: {f.technique}")
        print(f"  {'Evidence':12s}: {f.evidence}")
        if f.detail:
            print(f"  {'Detail':12s}: {f.detail}")
        if f.remediation:
            print(f"  {'Fix':12s}: {f.remediation}")

    def _write_output(self):
        try:
            if self.fmt == "json":
                data = [f.to_dict() for f in self.findings]
                with open(self.output_file, "w") as fh:
                    json.dump(data, fh, indent=2)
            else:
                with open(self.output_file, "w") as fh:
                    for f in self.findings:
                        fh.write(f"[{f.severity.upper()}] {f.name}\n")
                        fh.write(f"  Target    : {f.target}\n")
                        fh.write(f"  Technique : {f.technique}\n")
                        fh.write(f"  Evidence  : {f.evidence}\n")
                        if f.detail:
                            fh.write(f"  Detail    : {f.detail}\n")
                        if f.remediation:
                            fh.write(f"  Fix       : {f.remediation}\n")
                        fh.write("\n")
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Results written to {self.output_file}")
        except IOError as e:
            print(f"{Fore.RED}[E]{Style.RESET_ALL} Could not write output: {e}", file=sys.stderr)
