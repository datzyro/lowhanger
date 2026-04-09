"""
core/reporter.py — Output formatting and result aggregation.

Finding display format:
  [SEVERITY] Finding Name
    Target   : root target being scanned
    Affected : exact URL / endpoint / asset where the issue was observed
    Technique: how it was detected
    Cause    : what specifically was found (the header value, the response line,
               the matched string — concrete proof, not a prose description)

Supports: pretty terminal output (coloured), plain text, JSON.
"""

import json
import sys
from datetime import datetime
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

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

    Fields
    ------
    template_id : id of the template that produced this finding
    name        : short finding title
    severity    : critical | high | medium | low | info
    target      : the root target URL being scanned
    affected    : exact URL / endpoint / header / asset where the issue lives
    technique   : detection method (e.g. "plain HTTP request", "response header check")
    cause       : concrete proof — the actual value/string that triggered the finding
                  e.g. "Server: Apache/2.4.41"
                       "HTTP 302 → Location: https://evil.lowhanger.internal/"
                       "X-Frame-Options: absent | CSP frame-ancestors: absent"
    """

    def __init__(
        self,
        template_id: str,
        name:        str,
        severity:    str,
        target:      str,
        affected:    str,
        technique:   str,
        cause:       str,
    ):
        self.template_id = template_id
        self.name        = name
        self.severity    = severity.lower()
        self.target      = target
        self.affected    = affected
        self.technique   = technique
        self.cause       = cause
        self.timestamp   = datetime.utcnow().isoformat() + "Z"

    def to_dict(self) -> dict:
        return {
            "template_id": self.template_id,
            "name":        self.name,
            "severity":    self.severity,
            "target":      self.target,
            "affected":    self.affected,
            "technique":   self.technique,
            "cause":       self.cause,
            "timestamp":   self.timestamp,
        }


class Reporter:

    def __init__(self, verbose: bool = False, output_file: str = None, fmt: str = "pretty"):
        self.verbose     = verbose
        self.output_file = output_file
        self.fmt         = fmt
        self.findings    = []
        self._errors     = []

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        self._print_finding(finding)

    def info(self, msg: str):
        if self.verbose:
            print("{}{}{} {}".format(Fore.BLUE, "[*]", Style.RESET_ALL, msg))

    def debug(self, msg: str):
        if self.verbose:
            print("{}{}{} {}".format(Fore.WHITE, "[~]", Style.RESET_ALL, msg))

    def warn(self, msg: str):
        print("{}{}{} {}".format(Fore.YELLOW, "[!]", Style.RESET_ALL, msg), file=sys.stderr)

    def error(self, msg: str):
        self._errors.append(msg)
        print("{}{}{} {}".format(Fore.RED, "[E]", Style.RESET_ALL, msg), file=sys.stderr)

    def print_banner(self):
        banner = """{}
  ██╗      ██████╗ ██╗    ██╗██╗  ██╗ █████╗ ███╗   ██╗ ██████╗ ███████╗██████╗
  ██║     ██╔═══██╗██║    ██║██║  ██║██╔══██╗████╗  ██║██╔════╝ ██╔════╝██╔══██╗
  ██║     ██║   ██║██║ █╗ ██║███████║███████║██╔██╗ ██║██║  ███╗█████╗  ██████╔╝
  ██║     ██║   ██║██║███╗██║██╔══██║██╔══██║██║╚██╗██║██║   ██║██╔══╝  ██╔══██╗
  ███████╗╚██████╔╝╚███╔███╔╝██║  ██║██║  ██║██║ ╚████║╚██████╔╝███████╗██║  ██║
  ╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
{}{}  pick the fruit before they patch it  {}
""".format(Fore.RED, Style.RESET_ALL, Fore.WHITE, Style.RESET_ALL)
        print(banner)

    def print_summary(self):
        total  = len(self.findings)
        by_sev = {}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

        print("\n{}{}".format(Style.BRIGHT, "─" * 60))
        print("  SCAN COMPLETE — {} finding(s)".format(total))
        for sev in ("critical", "high", "medium", "low", "info"):
            count = by_sev.get(sev, 0)
            if count:
                col = SEVERITY_COLOUR.get(sev, "")
                print("  {}{:10s}{} {}".format(col, sev.upper(), Style.RESET_ALL, count))
        print("{}{}".format("─" * 60, Style.RESET_ALL))
        print()

        if self.output_file:
            self._write_output()

    # ------------------------------------------------------------------ #
    # Internal                                                             #
    # ------------------------------------------------------------------ #

    def _print_finding(self, f: Finding):
        col   = SEVERITY_COLOUR.get(f.severity, Fore.WHITE)
        label = "[{}]".format(f.severity.upper())
        print("\n{}{}{} {}{}{}".format(
            col, label, Style.RESET_ALL,
            Style.BRIGHT, f.name, Style.RESET_ALL,
        ))
        print("  {:<12}: {}".format("Target",    f.target))
        print("  {:<12}: {}".format("Affected",  f.affected))
        print("  {:<12}: {}".format("Technique", f.technique))
        print("  {:<12}: {}".format("Cause",     f.cause))

    def _write_output(self):
        try:
            if self.fmt == "json":
                with open(self.output_file, "w") as fh:
                    json.dump([f.to_dict() for f in self.findings], fh, indent=2)
            else:
                with open(self.output_file, "w") as fh:
                    for f in self.findings:
                        fh.write("[{}] {}\n".format(f.severity.upper(), f.name))
                        fh.write("  {:<12}: {}\n".format("Target",    f.target))
                        fh.write("  {:<12}: {}\n".format("Affected",  f.affected))
                        fh.write("  {:<12}: {}\n".format("Technique", f.technique))
                        fh.write("  {:<12}: {}\n".format("Cause",     f.cause))
                        fh.write("\n")
            print("{}[+]{} Results written to {}".format(
                Fore.GREEN, Style.RESET_ALL, self.output_file))
        except IOError as e:
            print("{}[E]{} Could not write output: {}".format(
                Fore.RED, Style.RESET_ALL, e), file=sys.stderr)