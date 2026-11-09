from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
_RANK = {name: i for i, name in enumerate(SEVERITIES)}


def severity_rank(severity: str) -> int:
    """Lower is more severe."""
    return _RANK[severity]


@dataclass
class Finding:
    agent: str
    check: str
    severity: str
    title: str
    detail: str = ""
    path: str = ""
    fix: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AgentReport:
    agent: str
    home: str
    found: bool
    config_path: str = ""
    findings: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def add(self, severity: str, check: str, title: str, detail: str = "",
            path: str = "", fix: str = "") -> None:
        self.findings.append(Finding(self.agent, check, severity, title, detail, path, fix))

    def to_dict(self) -> dict:
        return {
            "agent": self.agent,
            "home": self.home,
            "found": self.found,
            "config_path": self.config_path,
            "notes": self.notes,
            "findings": [f.to_dict() for f in self.findings],
        }
