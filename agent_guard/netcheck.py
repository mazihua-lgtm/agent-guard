"""Read-only look at which TCP ports are listening and on which address."""
from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import sys


def is_loopback(host: str) -> bool:
    host = host.strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.split("%")[0]).is_loopback
    except ValueError:
        return False


def is_wildcard(host: str) -> bool:
    return host.strip("[]") in ("*", "0.0.0.0", "::")


def parse_listeners(output: str) -> list:
    """Return [(host, port)] from `lsof -nP -iTCP -sTCP:LISTEN` or `ss -ltn` output."""
    found = []
    for line in output.splitlines():
        if "LISTEN" not in line:
            continue
        m = re.search(r"(\[[0-9a-fA-F:.%\w]+\]|[\d.]+|\*):(\d+)\s+\(LISTEN\)", line)  # lsof
        if not m:
            m = re.search(r"^LISTEN\s+\d+\s+\d+\s+(\[[0-9a-fA-F:.%\w]+\]|[\d.]+|\*):(\d+)\s", line)  # ss
        if m:
            found.append((m.group(1), int(m.group(2))))
    return found


def listeners() -> list:
    """Listening sockets on this machine, or None when no tool is available."""
    if sys.platform.startswith("linux") and shutil.which("ss"):
        cmd = ["ss", "-ltn"]
    elif shutil.which("lsof"):
        cmd = ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]
    else:
        return None
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return parse_listeners(res.stdout)


def exposed_ports(socks: list, ports: set) -> dict:
    """{port: [hosts]} for wanted ports listening on a non-loopback address."""
    out: dict = {}
    for host, port in socks:
        if port in ports and not is_loopback(host):
            out.setdefault(port, []).append(host)
    return out
