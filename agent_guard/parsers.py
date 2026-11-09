"""Small, dependency-free readers for the formats agent configs use.

Nothing here executes or modifies input. Parse errors raise ParseError.
"""
from __future__ import annotations

import re
from pathlib import Path


class ParseError(ValueError):
    pass


# ---------------------------------------------------------------- JSON5 ----

class _Json5:
    def __init__(self, text: str):
        self.s = text
        self.i = 0

    def fail(self, msg: str):
        raise ParseError(f"JSON5: {msg} at offset {self.i}")

    def ws(self) -> None:
        s, n = self.s, len(self.s)
        while self.i < n:
            c = s[self.i]
            if c.isspace() or c == "\ufeff":
                self.i += 1
            elif s.startswith("//", self.i):
                j = s.find("\n", self.i)
                self.i = n if j < 0 else j + 1
            elif s.startswith("/*", self.i):
                j = s.find("*/", self.i + 2)
                if j < 0:
                    self.fail("unterminated comment")
                self.i = j + 2
            else:
                break

    def value(self):
        self.ws()
        if self.i >= len(self.s):
            self.fail("unexpected end")
        c = self.s[self.i]
        if c == "{":
            return self.obj()
        if c == "[":
            return self.arr()
        if c in "\"'":
            return self.string()
        return self.atom()

    def obj(self):
        self.i += 1
        out: dict = {}
        while True:
            self.ws()
            if self.i >= len(self.s):
                self.fail("unterminated object")
            if self.s[self.i] == "}":
                self.i += 1
                return out
            key = self.string() if self.s[self.i] in "\"'" else self.ident()
            self.ws()
            if self.i >= len(self.s) or self.s[self.i] != ":":
                self.fail("expected ':'")
            self.i += 1
            out[key] = self.value()
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == ",":
                self.i += 1

    def arr(self):
        self.i += 1
        out: list = []
        while True:
            self.ws()
            if self.i >= len(self.s):
                self.fail("unterminated array")
            if self.s[self.i] == "]":
                self.i += 1
                return out
            out.append(self.value())
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == ",":
                self.i += 1

    def string(self) -> str:
        q = self.s[self.i]
        self.i += 1
        buf = []
        esc = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "0": "\0"}
        while self.i < len(self.s):
            c = self.s[self.i]
            if c == q:
                self.i += 1
                return "".join(buf)
            if c == "\\":
                self.i += 1
                if self.i >= len(self.s):
                    break
                e = self.s[self.i]
                if e == "u" and re.fullmatch(r"[0-9a-fA-F]{4}", self.s[self.i + 1:self.i + 5]):
                    buf.append(chr(int(self.s[self.i + 1:self.i + 5], 16)))
                    self.i += 5
                    continue
                if e == "\n":
                    self.i += 1
                    continue
                buf.append(esc.get(e, e))
                self.i += 1
                continue
            buf.append(c)
            self.i += 1
        self.fail("unterminated string")

    def ident(self) -> str:
        m = re.compile(r"[A-Za-z_$][\w$]*").match(self.s, self.i)
        if not m:
            self.fail("expected key")
        self.i = m.end()
        return m.group(0)

    def atom(self):
        m = re.compile(r"[^\s,\]\}:/]+").match(self.s, self.i)
        if not m:
            self.fail("unexpected character")
        tok = m.group(0)
        self.i = m.end()
        if tok == "true":
            return True
        if tok == "false":
            return False
        if tok == "null":
            return None
        try:
            if re.fullmatch(r"[+-]?0[xX][0-9a-fA-F]+", tok):
                return int(tok, 16)
            if re.fullmatch(r"[+-]?\d+", tok):
                return int(tok)
            return float(tok)
        except ValueError:
            self.fail(f"bad token {tok!r}")


def load_json5(text: str):
    p = _Json5(text)
    v = p.value()
    p.ws()
    if p.i != len(p.s):
        p.fail("trailing data")
    return v


# ----------------------------------------------------------------- YAML ----

def _strip_comment(line: str) -> str:
    quote = ""
    for i, c in enumerate(line):
        if quote:
            if c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i]
    return line


def _scalar(tok: str):
    tok = tok.strip()
    if tok == "":
        return None
    if tok[0] in "\"'" and tok[-1] == tok[0] and len(tok) >= 2:
        return tok[1:-1]
    low = tok.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~"):
        return None
    if tok == "{}":
        return {}
    if tok == "[]":
        return []
    if tok[0] == "[" and tok[-1] == "]":
        return [_scalar(x) for x in _split_flow(tok[1:-1])]
    if re.fullmatch(r"[+-]?\d+", tok):
        return int(tok)
    if re.fullmatch(r"[+-]?\d*\.\d+", tok):
        return float(tok)
    return tok


def _split_flow(body: str) -> list:
    parts, cur, quote, depth = [], [], "", 0
    for c in body:
        if quote:
            cur.append(c)
            if c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
            cur.append(c)
        elif c in "[{":
            depth += 1
            cur.append(c)
        elif c in "]}":
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return parts


def _split_key(text: str):
    """Split 'key: value' on the first colon outside quotes; None if no key."""
    quote = ""
    for i, c in enumerate(text):
        if quote:
            if c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c == ":" and (i + 1 == len(text) or text[i + 1] in " \t"):
            return text[:i].strip().strip("\"'"), text[i + 1:].strip()
    return None


def load_yaml_lite(text: str):
    """Block mappings, nested maps, scalar/flow lists and `- item` lists of scalars.

    Block scalars (| and >) are read as a single string. A `- key: value` list item
    is kept as the raw string. That covers the settings agent-guard reads; it is not
    a general YAML parser.
    """
    lines = []
    for raw in text.splitlines():
        if raw.strip() in ("---", "..."):
            continue
        clean = _strip_comment(raw).rstrip()
        if clean.strip():
            lines.append((len(clean) - len(clean.lstrip(" ")), clean.strip()))
    pos = 0

    def block(indent: int):
        nonlocal pos
        if pos < len(lines) and lines[pos][1].startswith("- ") or (
                pos < len(lines) and lines[pos][1] == "-"):
            out_list = []
            while pos < len(lines) and lines[pos][0] == indent and (
                    lines[pos][1].startswith("- ") or lines[pos][1] == "-"):
                out_list.append(_scalar(lines[pos][1][1:]))
                pos += 1
            return out_list
        out: dict = {}
        while pos < len(lines) and lines[pos][0] == indent:
            kv = _split_key(lines[pos][1])
            if kv is None:
                raise ParseError(f"YAML: cannot read line {lines[pos][1]!r}")
            key, rest = kv
            pos += 1
            if rest in ("|", ">", "|-", ">-", "|+", ">+"):
                body = []
                while pos < len(lines) and lines[pos][0] > indent:
                    body.append(lines[pos][1])
                    pos += 1
                out[key] = "\n".join(body)
            elif rest == "":
                if pos < len(lines) and (lines[pos][0] > indent or (
                        lines[pos][0] == indent and lines[pos][1].startswith("-"))):
                    out[key] = block(lines[pos][0])
                else:
                    out[key] = None
            else:
                out[key] = _scalar(rest)
        return out

    if not lines:
        return {}
    result = block(lines[0][0])
    if pos != len(lines):
        raise ParseError("YAML: inconsistent indentation")
    return result


def load_yaml(text: str):
    try:
        import yaml  # type: ignore
    except ImportError:
        return load_yaml_lite(text)
    try:
        return yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ParseError(f"YAML: {exc}") from exc


# --------------------------------------------------------------- dotenv ----

def load_dotenv(text: str) -> dict:
    out = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        val = val.strip()
        if val[:1] in "\"'" and val.endswith(val[0]) and len(val) >= 2:
            val = val[1:-1]
        else:
            val = re.split(r"\s+#", val, maxsplit=1)[0].strip()
        out[key.strip()] = val
    return out


# -------------------------------------------------------------- helpers ----

def read_text(path: Path, limit: int = 2_000_000) -> str:
    with open(path, "rb") as fh:
        data = fh.read(limit)
    return data.decode("utf-8", errors="replace")


def dig(data, *keys, default=None):
    cur = data
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return isinstance(value, str) and value.strip().lower() in ("1", "true", "yes", "on")
