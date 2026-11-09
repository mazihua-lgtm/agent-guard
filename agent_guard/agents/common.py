from __future__ import annotations

import os
import stat
from pathlib import Path

from .. import secrets, skills
from ..model import AgentReport



def expand(path: str, home: Path) -> Path:
    if path.startswith("~"):
        return home / path[2:] if path.startswith("~/") else home
    return Path(path)


def loose_mode(path: Path):
    """Return the octal mode string when group/others can access the file, else None."""
    if os.name != "posix":
        return None
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None
    return format(mode, "04o") if mode & 0o077 else None


def check_permissions(rep: AgentReport, paths, severity: str = "medium") -> None:
    for p in paths:
        if not p.exists():
            continue
        mode = loose_mode(p)
        if mode:
            kind = "directory" if p.is_dir() else "file"
            rep.add(severity, "permissions", f"{p.name} {kind} is accessible to other users (mode {mode})",
                    path=str(p), fix=f"chmod {'700' if p.is_dir() else '600'} {p}")


def scan_secrets(rep: AgentReport, path: Path, severity: str, title: str, fix: str) -> None:
    if not path.is_file():
        return
    hits = secrets.scan_file(path)
    for h in hits[:20]:
        rep.add(severity, "secrets", f"{title}: {h.label} (line {h.line})", detail=h.masked, path=str(path), fix=fix)
    if len(hits) > 20:
        rep.add("info", "secrets", f"{len(hits) - 20} more hits not shown", path=str(path))


def review_dirs(rep: AgentReport, label: str, roots) -> int:
    """Review every skill under the given roots. Returns the number of skills reviewed."""
    count = 0
    for root in roots:
        for sd in skills.find_skill_dirs(root):
            count += 1
            for it in skills.review_skill(sd):
                rep.add(it.severity, "skills", f"{label} '{it.skill}': {it.title}",
                        detail=f"{it.file}:{it.line}  {it.snippet}", path=str(sd),
                        fix="Read the file, and remove the skill if you did not write it or cannot vouch for its source.")
    return count


def review_tree(rep: AgentReport, label: str, directory: Path) -> None:
    """Review one directory as a unit (plugins and hooks have no SKILL.md)."""
    if not directory.is_dir():
        return
    for it in skills.review_skill(directory):
        rep.add(it.severity, "skills", f"{label} '{it.skill}': {it.title}",
                detail=f"{it.file}:{it.line}  {it.snippet}", path=str(directory),
                fix="Read the file, and remove it if you did not write it or cannot vouch for its source.")
