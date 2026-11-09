from __future__ import annotations

import json

from . import __version__
from .model import SEVERITIES, AgentReport, severity_rank

_COLOR = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
_RESET = "\033[0m"


def all_findings(reports: list) -> list:
    items = [f for r in reports for f in r.findings]
    return sorted(items, key=lambda f: (severity_rank(f.severity), f.agent, f.check, f.title))


def counts(reports: list) -> dict:
    c = {s: 0 for s in SEVERITIES}
    for f in all_findings(reports):
        c[f.severity] += 1
    return c


def to_json(reports: list) -> str:
    return json.dumps({"tool": "agent-guard", "version": __version__, "summary": counts(reports),
                       "agents": [r.to_dict() for r in reports]}, indent=2, ensure_ascii=False)


def to_markdown(reports: list) -> str:
    c = counts(reports)
    out = [f"# agent-guard report", "",
           "Read-only scan of this machine. Credential values are masked.", "",
           "| " + " | ".join(SEVERITIES) + " |", "|" + "---|" * len(SEVERITIES),
           "| " + " | ".join(str(c[s]) for s in SEVERITIES) + " |", ""]
    for r in reports:
        out.append(f"## {r.agent}")
        if not r.found:
            out += ["", f"Not found (looked in `{r.home}`).", ""]
            continue
        out += ["", f"Home: `{r.home}`  ", f"Config: `{r.config_path}`", ""]
        for n in r.notes:
            out.append(f"- Note: {n}")
        if r.notes:
            out.append("")
        if not r.findings:
            out += ["No findings.", ""]
        for f in sorted(r.findings, key=lambda f: severity_rank(f.severity)):
            out.append(f"### [{f.severity.upper()}] {f.title}")
            out.append("")
            out.append(f"- Check: {f.check}")
            if f.path:
                out.append(f"- Where: `{f.path}`")
            if f.detail:
                out.append(f"- Detail: {f.detail}")
            if f.fix:
                out.append(f"- Fix: {f.fix}")
            out.append("")
    return "\n".join(out)


def to_text(reports: list, color: bool = False) -> str:
    def paint(sev: str, text: str) -> str:
        return f"{_COLOR[sev]}{text}{_RESET}" if color else text

    out = []
    for r in reports:
        out.append(f"== {r.agent}: " + (r.home if r.found else f"not found ({r.home})"))
        if not r.found:
            continue
        for n in r.notes:
            out.append(f"   note: {n}")
        if not r.findings:
            out.append("   no findings")
        for f in sorted(r.findings, key=lambda f: severity_rank(f.severity)):
            out.append(f"   {paint(f.severity, f'[{f.severity.upper():8}]')} {f.title}")
            if f.detail:
                out.append(f"              {f.detail}")
            if f.path:
                out.append(f"              at {f.path}")
            if f.fix:
                out.append(f"              fix: {f.fix}")
    c = counts(reports)
    out += ["", "Summary: " + ", ".join(f"{c[s]} {s}" for s in SEVERITIES)]
    return "\n".join(out)
