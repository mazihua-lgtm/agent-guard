"""Static review of skill/plugin directories. Files are read, never executed."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .parsers import read_text

_TEXT_SUFFIXES = {".md", ".txt", ".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts",
                  ".json", ".json5", ".yaml", ".yml", ".toml", ".ps1", ""}
_MAX_FILE = 512 * 1024
_MAX_FILES_PER_SKILL = 400

_NET = r"(?:curl|wget|nc|ncat|scp|rsync|Invoke-WebRequest|Invoke-RestMethod|requests\.(?:post|put)|fetch\(|axios)"
_CRED_PATH = (r"(?:~|\$HOME|/home/\w+|/Users/\w+)?/?\.(?:ssh/(?:id_|config)|aws/credentials|npmrc|netrc|"
              r"gnupg|docker/config\.json|kube/config|hermes/(?:\.env|auth\.json)|openclaw/(?:\.env|openclaw\.json))")

# (id, severity, title, regex, applies-to-md). Regexes run per line.
_LINE_RULES = [
    ("pipe-to-shell", "high", "Downloads and pipes straight into a shell",
     re.compile(r"(?<!\\)(?:curl|wget)\b[^\n|;]*(?<!\\)\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b(?!\w)|"
                r"(?:curl|wget)\b[^\n|;]*(?<!\\)\|\s*(?:sudo\s+)?python3?\s*(?:-\s*)?(?:$|[;&)])|"
                r"(?:iwr|Invoke-WebRequest)\b[^\n|]*\|\s*(?:iex|Invoke-Expression)", re.I)),
    ("b64-exec", "high", "Decodes base64 and executes it",
     re.compile(r"base64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|"
                r"(?:eval|exec)\s*\(?[^\n]{0,80}b64decode|"
                r"b64decode\([^\n]*\)[^\n]*\b(?:exec|eval)\b|"
                r"\batob\([^\n]*\)[^\n]*\beval\b|"
                r"FromBase64String[^\n]*(?:iex|Invoke-Expression)", re.I)),
    ("reverse-shell", "critical", "Looks like a reverse shell",
     re.compile(r"/dev/tcp/|\bnc(?:at)?\b[^\n]*\s-e\s|bash\s+-i\s+>&|mkfifo\s+\S+;?\s*(?:nc|ncat)\b", re.I)),
    ("cred-exfil", "high", "Reads a credential file and sends data over the network",
     re.compile(rf"(?:{_NET}[^\n]*{_CRED_PATH})|(?:{_CRED_PATH}[^\n]*{_NET})", re.I)),
    ("env-exfil", "high", "Sends environment variables over the network",
     re.compile(r"(?:\benv\b|\bprintenv\b|os\.environ|process\.env)[^\n]*\|\s*(?:curl|wget|nc)\b|"
                r"(?:curl|wget)\b[^\n]*(?:-d|--data[\w-]*)\s*[\"']?(?:\$\(\s*env|`env|@-)", re.I)),
    ("destructive", "high", "Destructive delete of a broad path",
     re.compile(r"\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(?:--no-preserve-root\s+)?(?:/|~|\$HOME)(?:\s|$|\*)", re.I)),
    ("exfil-endpoint", "medium", "Mentions a paste/webhook/tunnel endpoint commonly used to receive stolen data",
     re.compile(r"discord(?:app)?\.com/api/webhooks/|webhook\.site|requestbin|pastebin\.com/api|"
                r"hooks\.slack\.com/services/|\bngrok(?:-free)?\.(?:app|io|dev)\b|transfer\.sh|interact\.sh|oast\.", re.I)),
    ("raw-ip-url", "low", "Fetches from a raw IP address",
     re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?::\d+)?/", re.I)),
    ("prompt-injection", "low", "Contains instruction-override wording aimed at the model",
     re.compile(r"ignore (?:all |any )?(?:previous|prior|above) (?:instructions|rules)|"
                r"disregard (?:the |all )?(?:system prompt|previous instructions)|"
                r"do not (?:tell|inform|mention (?:this )?to) the user|"
                r"without (?:asking|telling) the user", re.I)),
]
# In documentation a risky line is usually an instruction to the reader, not code that runs by itself.
_DOC_DOWNGRADE = {"pipe-to-shell": "medium", "destructive": "medium", "exfil-endpoint": "low", "raw-ip-url": "info"}
_PERSIST = re.compile(r"(?:>>?\s*~?/?[\w./$]*\.(?:bashrc|zshrc|zprofile|profile)\b|crontab\s+-|"
                      r"launchctl\s+load|LaunchAgents/|systemctl\s+--user\s+enable)", re.I)


@dataclass
class SkillIssue:
    skill: str
    file: str
    line: int
    rule: str
    severity: str
    title: str
    snippet: str


def find_skill_dirs(root: Path) -> list:
    """Directories under root that hold a SKILL.md (up to 6 levels deep), skipping hidden hub state."""
    out = []
    if not root.is_dir():
        return out
    base_depth = len(root.parts)
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        if (d / "SKILL.md").is_file() and d != root:
            out.append(d)
            continue
        for e in entries:
            if e.name.startswith(".") or e.is_symlink() and not e.exists():
                continue
            if e.is_dir() and len(e.parts) - base_depth < 6:
                stack.append(e)
    return sorted(out)


def _iter_files(skill_dir: Path):
    n = 0
    for p in sorted(skill_dir.rglob("*")):
        if n >= _MAX_FILES_PER_SKILL:
            return
        try:
            if p.is_symlink() or not p.is_file():
                continue
            if p.suffix.lower() not in _TEXT_SUFFIXES or p.stat().st_size > _MAX_FILE:
                continue
        except OSError:
            continue
        n += 1
        yield p


def review_skill(skill_dir: Path) -> list:
    issues = []
    seen = set()
    for f in _iter_files(skill_dir):
        try:
            text = read_text(f, _MAX_FILE)
        except OSError:
            continue
        rel = str(f.relative_to(skill_dir))
        for lineno, line in enumerate(text.splitlines(), 1):
            if len(line) > 3000:
                line = line[:3000]
            for rid, sev, title, rx in _LINE_RULES:
                if rx.search(line) and (rid, rel) not in seen:
                    seen.add((rid, rel))
                    if f.suffix.lower() in (".md", ".txt"):
                        sev = _DOC_DOWNGRADE.get(rid, sev)
                    issues.append(SkillIssue(skill_dir.name, rel, lineno, rid, sev, title, line.strip()[:160]))
            if _PERSIST.search(line) and ("persist", rel) not in seen:
                seen.add(("persist", rel))
                issues.append(SkillIssue(skill_dir.name, rel, lineno, "persistence", "medium",
                                         "Writes to a shell profile, cron or login item", line.strip()[:160]))
    return issues
