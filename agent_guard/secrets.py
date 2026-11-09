"""Find credentials stored in plain text. Values are never returned, only masked."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .parsers import read_text

# (label, pattern). Specific token shapes first; the generic assignment rule is last.
_RULES = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI-style API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("Hardcoded credential assignment", re.compile(
        r"""(?ix)
        ["']?\b[\w.-]*(?:api[_-]?key|secret|token|passw(?:or)?d|passwd)[\w.-]*["']?
        \s*[:=]\s*
        ["']?(?!\$\{|\$\(|<|\{\{|%|env:|process\.env|os\.environ)([A-Za-z0-9_\-./+=]{16,})["']?
        """)),
]
_PLACEHOLDER = re.compile(r"(?i)(example|changeme|your[_-]|xxxx|placeholder|dummy|<.*>|\*{4,}|\.{3})")


@dataclass
class SecretHit:
    label: str
    line: int
    masked: str


def mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "****"
    return f"{value[:3]}...({len(value)} chars)"


def scan_text(text: str) -> list:
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            line = line[:4000]
        for label, rx in _RULES:
            m = rx.search(line)
            if not m:
                continue
            token = m.group(m.lastindex) if m.lastindex else m.group(0)
            if _PLACEHOLDER.search(token):
                continue
            hits.append(SecretHit(label, lineno, mask(token) if label != "Private key block" else "[key block]"))
            break  # one finding per line
    return hits


def scan_file(path: Path, limit: int = 1_000_000) -> list:
    try:
        return scan_text(read_text(path, limit))
    except OSError:
        return []
