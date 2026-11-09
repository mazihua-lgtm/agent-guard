from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, netcheck, report
from .agents import AGENTS
from .model import SEVERITIES, severity_rank


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agent-guard",
                                description="Read-only security audit of personal AI agents installed on this machine.")
    p.add_argument("--agent", action="append", choices=sorted(AGENTS), help="limit to one agent (repeatable)")
    p.add_argument("--home", type=Path, default=Path.home(), help="treat this directory as the user's home (default: your home)")
    p.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    p.add_argument("--output", "-o", type=Path, help="write the report to this file instead of stdout")
    p.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide findings below this level")
    p.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 when a finding at this level or worse exists")
    p.add_argument("--no-network", action="store_true", help="skip the listening-port check")
    p.add_argument("--version", action="version", version=f"agent-guard {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    sockets = None if args.no_network else netcheck.listeners()
    env = dict(os.environ)
    names = args.agent or sorted(AGENTS)
    reports = [AGENTS[n](args.home, env, sockets) for n in names]

    cutoff = severity_rank(args.min_severity)
    for r in reports:
        r.findings = [f for f in r.findings if severity_rank(f.severity) <= cutoff]

    if args.format == "json":
        text = report.to_json(reports)
    elif args.format == "markdown":
        text = report.to_markdown(reports)
    else:
        text = report.to_text(reports, color=args.output is None and sys.stdout.isatty())

    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        print(text)

    if args.fail_on:
        limit = severity_rank(args.fail_on)
        if any(severity_rank(f.severity) <= limit for r in reports for f in r.findings):
            return 1
    return 0
