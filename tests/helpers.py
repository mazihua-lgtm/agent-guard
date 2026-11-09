import os
import tempfile
from pathlib import Path


def make_home() -> Path:
    d = Path(tempfile.mkdtemp(prefix="agent-guard-test-"))
    return d


def write(path: Path, text: str, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    os.chmod(path, mode)
    return path


def titles(report, severity=None):
    return [f.title for f in report.findings if severity is None or f.severity == severity]
