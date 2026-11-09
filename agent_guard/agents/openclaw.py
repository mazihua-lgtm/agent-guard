"""OpenClaw checks. Paths and keys come from docs.openclaw.ai (see docs/SOURCES.md)."""
from __future__ import annotations

from pathlib import Path

from .. import netcheck
from ..model import AgentReport
from ..parsers import ParseError, dig, load_dotenv, load_json5, read_text, truthy
from . import common

DEFAULT_PORT = 18789


def state_dir(home: Path, env: dict) -> Path:
    return common.expand(env.get("OPENCLAW_STATE_DIR") or "~/.openclaw", home)


def config_path(home: Path, env: dict) -> Path:
    if env.get("OPENCLAW_CONFIG_PATH"):
        return common.expand(env["OPENCLAW_CONFIG_PATH"], home)
    return state_dir(home, env) / "openclaw.json"


def _is_ref(value) -> bool:
    """True for ${ENV} templates and SecretRef objects, which do not hold the secret itself."""
    return isinstance(value, dict) or (isinstance(value, str) and value.strip().startswith("${"))


def audit(home: Path, env: dict, sockets) -> AgentReport:
    sdir = state_dir(home, env)
    cfg_path = config_path(home, env)
    rep = AgentReport("openclaw", str(sdir), sdir.exists() or cfg_path.exists(), str(cfg_path))
    if not rep.found:
        return rep

    cfg: dict = {}
    if cfg_path.is_file():
        try:
            parsed = load_json5(read_text(cfg_path))
            cfg = parsed if isinstance(parsed, dict) else {}
        except (ParseError, OSError) as exc:
            rep.add("info", "config", "Could not parse openclaw.json; config checks skipped",
                    detail=str(exc), path=str(cfg_path))
    else:
        rep.notes.append("openclaw.json not found; documented defaults apply (loopback bind, auth required).")

    dotenv_path = sdir / ".env"
    dotenv = load_dotenv(read_text(dotenv_path)) if dotenv_path.is_file() else {}

    gw = dig(cfg, "gateway", default={}) or {}
    bind = gw.get("bind") if isinstance(gw, dict) else None
    port = gw.get("port", DEFAULT_PORT) if isinstance(gw, dict) else DEFAULT_PORT
    if not isinstance(port, int):
        port = DEFAULT_PORT
    auth_mode = dig(gw, "auth", "mode")
    tailscale = dig(gw, "tailscale", "mode")

    non_loopback_bind = bind in ("lan", "auto", "tailnet", "custom")
    # `auto` only resolves to 0.0.0.0 inside a container; on a normal host it is loopback.
    if bind == "lan":
        rep.add("high", "exposure", "Gateway binds to all interfaces (gateway.bind = \"lan\", 0.0.0.0)",
                detail=f"port {port}", path=str(cfg_path),
                fix='Set gateway.bind to "loopback", and reach it through an SSH tunnel or Tailscale Serve.')
    elif bind == "tailnet":
        rep.add("low", "exposure", "Gateway binds to the Tailscale address (gateway.bind = \"tailnet\")",
                path=str(cfg_path), fix="Fine for a private tailnet; make sure only your devices are in it.")
    elif bind == "custom":
        rep.add("medium", "exposure", "Gateway binds to a custom address (gateway.bind = \"custom\")",
                path=str(cfg_path), fix="Confirm the address is loopback or a private interface you control.")
    elif bind == "auto":
        rep.add("low", "exposure", 'gateway.bind = "auto": resolves to 0.0.0.0 inside a container',
                path=str(cfg_path), fix='Set gateway.bind to "loopback" unless the container needs the wildcard listener.')

    if auth_mode == "none":
        sev = "critical" if non_loopback_bind else "medium"
        rep.add(sev, "exposure", "Gateway auth is disabled (gateway.auth.mode = \"none\")",
                detail="Anyone who can reach the port gets operator access, including /tools/invoke.",
                path=str(cfg_path), fix='Set gateway.auth.mode to "token" and keep the bind on loopback.')

    if tailscale == "funnel":
        rep.add("high", "exposure", "Tailscale Funnel exposes the gateway to the public internet",
                path=str(cfg_path), fix='Use gateway.tailscale.mode = "serve" (tailnet only) or "off".')

    token = dig(gw, "auth", "token")
    if isinstance(token, str) and token and not _is_ref(token):
        sev = "medium" if len(token) < 24 else "low"
        why = "short, guessable token" if len(token) < 24 else "token stored as plain text in the config file"
        rep.add(sev, "secrets", f"gateway.auth.token: {why}", detail=f"{token[:2]}**** ({len(token)} chars)",
                path=str(cfg_path), fix="Reference it from the environment (${VAR}) or a SecretRef, and use a long random value.")
    password = dig(gw, "auth", "password")
    if isinstance(password, str) and password and not _is_ref(password):
        rep.add("medium", "secrets", "gateway.auth.password stored as plain text in the config file",
                path=str(cfg_path), fix="Use OPENCLAW_GATEWAY_PASSWORD or a SecretRef instead.")

    flags = [
        (("controlUi", "allowExternalEmbedUrls"), "high", "Control UI may embed external URLs"),
        (("controlUi", "dangerouslyAllowHostHeaderOriginFallback"), "high", "Control UI trusts the Host header for origin checks"),
        (("terminal", "enabled"), "medium", "Browser terminal is enabled (gateway.terminal.enabled)"),
        (("allowRealIpFallback",), "medium", "gateway.allowRealIpFallback trusts X-Real-IP when the proxy header is missing"),
    ]
    for keys, sev, title in flags:
        if truthy(dig(gw, *keys)):
            rep.add(sev, "exposure", title, path=str(cfg_path), fix=f"Remove gateway.{'.'.join(keys)} or set it to false.")
    if dig(gw, "nodes", "pairing", "autoApproveCidrs"):
        rep.add("medium", "exposure", "Node pairing is auto-approved for configured CIDR ranges",
                detail=str(dig(gw, "nodes", "pairing", "autoApproveCidrs")), path=str(cfg_path),
                fix="Keep the ranges as small as possible, or remove them and approve nodes by hand.")

    sandbox = dig(cfg, "agents", "defaults", "sandbox", "mode", default="off")
    if sandbox == "off":
        rep.add("medium", "isolation", "Agent sandbox is off (agents.defaults.sandbox.mode = off, the default)",
                detail="Tools run on the gateway host with your user's permissions.",
                path=str(cfg_path), fix='Set agents.defaults.sandbox.mode to "non-main" or "all" if a sandbox runtime is installed.')

    if sockets is not None:
        hits = netcheck.exposed_ports(sockets, {port})
        for p, hosts in hits.items():
            rep.add("high", "exposure", f"Port {p} is listening on a non-loopback address",
                    detail=", ".join(sorted(set(hosts))),
                    fix="Bind the gateway to loopback, or firewall the port.")
    else:
        rep.notes.append("Could not list listening ports (no ss/lsof); live exposure check skipped.")

    common.check_permissions(rep, [sdir, cfg_path, dotenv_path])
    common.scan_secrets(rep, cfg_path, "medium", "Plain-text credential in openclaw.json",
                        "Move it to ~/.openclaw/.env or a SecretRef and rotate the key.")
    workspace = common.expand(str(dig(cfg, "agents", "defaults", "workspace", default="~/.openclaw/workspace")), home)
    for md in (workspace.glob("*.md") if workspace.is_dir() else []):
        common.scan_secrets(rep, md, "high", "Credential in an agent memory/workspace file",
                            "Remove it and rotate the key; the agent can read and repeat these files.")

    roots = [sdir / "skills", home / ".agents" / "skills", workspace / "skills", workspace / ".agents" / "skills"]
    extra = dig(cfg, "skills", "load", "extraDirs", default=[]) or []
    roots += [common.expand(str(x), home) for x in extra if isinstance(x, str)]
    n = common.review_dirs(rep, "Skill", roots)
    rep.notes.append(f"Reviewed {n} skill(s) under {len([r for r in roots if r.is_dir()])} directories.")

    load_paths = dig(cfg, "plugins", "load", "paths", default=[]) or []
    for lp in load_paths:
        if isinstance(lp, str):
            rep.add("low", "plugins", "Plugin loaded from a local path (plugins.load.paths)", detail=lp, path=str(cfg_path),
                    fix="Plugins run code inside the gateway; keep only ones you wrote or reviewed.")
            common.review_tree(rep, "Plugin", common.expand(lp, home))
    return rep
