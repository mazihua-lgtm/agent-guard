"""Hermes Agent checks. Paths, keys and defaults come from hermes-agent.nousresearch.com/docs (see docs/SOURCES.md)."""
from __future__ import annotations

from pathlib import Path

from .. import netcheck
from ..model import AgentReport
from ..parsers import ParseError, dig, load_dotenv, load_yaml, read_text, truthy
from . import common

API_PORT, WEBHOOK_PORT, DASHBOARD_PORT, WEBAPP_PORT = 8642, 8644, 9119, 9120

CREDENTIAL_FILES = [
    "auth.json", ".anthropic_oauth.json", "google_token.json", "google_client_secret.json",
    "bws_cache.json", "op_cache.json", "webhook_subscriptions.json",
    "auth/google_oauth.json", "vault", "mcp-tokens", "pairing",
]


def hermes_home(home: Path, env: dict) -> Path:
    return common.expand(env.get("HERMES_HOME") or "~/.hermes", home)


def audit(home: Path, env: dict, sockets) -> AgentReport:
    hh = hermes_home(home, env)
    cfg_path = hh / "config.yaml"
    rep = AgentReport("hermes", str(hh), hh.exists(), str(cfg_path))
    if not rep.found:
        return rep

    cfg: dict = {}
    if cfg_path.is_file():
        try:
            parsed = load_yaml(read_text(cfg_path))
            cfg = parsed if isinstance(parsed, dict) else {}
        except (ParseError, OSError) as exc:
            rep.add("info", "config", "Could not parse config.yaml; config checks skipped",
                    detail=str(exc), path=str(cfg_path))
    else:
        rep.notes.append("config.yaml not found; documented defaults apply.")

    env_path = hh / ".env"
    dotenv = load_dotenv(read_text(env_path)) if env_path.is_file() else {}

    # --- who may talk to the agent
    allow_all = [k for k, v in dotenv.items() if k.endswith("ALLOW_ALL_USERS") and truthy(v)]
    if truthy(dig(cfg, "gateway", "allow_all_users")) or truthy(cfg.get("allow_all_users")):
        allow_all.append("config.yaml allow_all_users")
    for name in allow_all:
        rep.add("high", "access", f"{name} is on: anyone who can message the bot is allowed",
                detail="The docs advise against this for bots that have terminal access.",
                path=str(env_path if name in dotenv else cfg_path),
                fix="Remove it and list your own user ids in <PLATFORM>_ALLOWED_USERS.")
    if "GATEWAY_ALLOWED_USERS" in dotenv and "*" in [x.strip() for x in dotenv["GATEWAY_ALLOWED_USERS"].split(",")]:
        rep.add("high", "access", "GATEWAY_ALLOWED_USERS contains *", path=str(env_path),
                fix="List explicit user ids.")

    # --- what the agent may do without asking
    mode = dig(cfg, "approvals", "mode", default="smart")
    if mode is False or mode == "off":  # PyYAML reads an unquoted `off` as False
        rep.add("high", "approvals", "approvals.mode is off: dangerous shell commands run without any check",
                detail="Equivalent to --yolo.", path=str(cfg_path), fix="Use smart or manual.")
    if truthy(dotenv.get("HERMES_YOLO_MODE")):
        rep.add("high", "approvals", "HERMES_YOLO_MODE is set in .env", path=str(env_path),
                fix="Remove it; approvals are skipped on every start.")
    for key in ("cron_mode", "single_query_mode", "unattended_mode"):
        if dig(cfg, "approvals", key) == "approve":
            rep.add("high" if key == "unattended_mode" else "medium", "approvals",
                    f"approvals.{key} = approve: dangerous commands are auto-approved in that context",
                    path=str(cfg_path), fix=f"Set approvals.{key} to deny (the default).")
    if truthy(dig(cfg, "security", "allow_private_urls")):
        rep.add("medium", "network", "security.allow_private_urls is on: the agent may fetch internal/RFC1918 addresses",
                path=str(cfg_path), fix="Turn it off unless you need local services.")
    if truthy(dig(cfg, "security", "allow_lazy_installs")):
        rep.add("low", "approvals", "security.allow_lazy_installs is on: packages may be installed on demand",
                path=str(cfg_path), fix="Turn it off if you do not rely on it.")

    # --- network surfaces
    if truthy(dotenv.get("API_SERVER_ENABLED")):
        host = dotenv.get("API_SERVER_HOST", "127.0.0.1")
        key = dotenv.get("API_SERVER_KEY", "")
        if not key:
            rep.add("critical", "exposure", "API server is enabled without API_SERVER_KEY", path=str(env_path),
                    fix="Set a long random API_SERVER_KEY (openssl rand -hex 32).")
        elif len(key) < 16:
            rep.add("medium", "secrets", f"API_SERVER_KEY is short ({len(key)} chars)", path=str(env_path),
                    fix="Use at least 32 random hex characters.")
        if not netcheck.is_loopback(host):
            rep.add("high", "exposure", f"API server bind address is {host} (reachable from the network)",
                    detail=f"port {dotenv.get('API_SERVER_PORT', API_PORT)}; the key is the only protection",
                    path=str(env_path), fix="Use API_SERVER_HOST=127.0.0.1 and a reverse proxy or tunnel if remote access is needed.")
        if "*" in [o.strip() for o in dotenv.get("API_SERVER_CORS_ORIGINS", "").split(",")]:
            rep.add("high", "exposure", "API_SERVER_CORS_ORIGINS allows every origin", path=str(env_path),
                    fix="List the exact origins of your front end.")
    if truthy(dotenv.get("WEBHOOK_ENABLED")):
        rep.add("low" if dotenv.get("WEBHOOK_SECRET") else "medium", "exposure",
                "Webhook adapter is enabled" + ("" if dotenv.get("WEBHOOK_SECRET") else " and no global WEBHOOK_SECRET is set"),
                detail=f"port {dotenv.get('WEBHOOK_PORT', WEBHOOK_PORT)}; per-route secrets in config.yaml may still cover it",
                path=str(env_path), fix="Give every route an HMAC secret and keep the port behind a proxy.")
    webapp = dig(cfg, "webapp", default={}) or {}
    if truthy(webapp.get("enabled")) and isinstance(webapp.get("host"), str) and not netcheck.is_loopback(webapp["host"]):
        rep.add("medium", "exposure", f"Webapp listens on {webapp['host']}",
                detail="Needs a dashboard sign-in provider; without one the gateway should serve native clients only.",
                path=str(cfg_path), fix="Keep host at 127.0.0.1 unless sign-in is configured.")

    if sockets is not None:
        # port -> (severity, what). Dashboard/Webapp sit behind a sign-in when bound to a non-loopback address.
        ports = {API_PORT: ("high", "API server"), WEBHOOK_PORT: ("medium", "webhook adapter"),
                 DASHBOARD_PORT: ("medium", "dashboard"), WEBAPP_PORT: ("medium", "Webapp")}
        for key, what in (("API_SERVER_PORT", "API server"), ("WEBHOOK_PORT", "webhook adapter")):
            if str(dotenv.get(key, "")).isdigit():
                ports[int(dotenv[key])] = ports[API_PORT if key == "API_SERVER_PORT" else WEBHOOK_PORT]
        if isinstance(webapp.get("port"), int):
            ports[webapp["port"]] = ports[WEBAPP_PORT]
        for p, hosts in sorted(netcheck.exposed_ports(sockets, set(ports)).items()):
            sev, what = ports[p]
            rep.add(sev, "exposure", f"Port {p} ({what}) is listening on a non-loopback address",
                    detail=", ".join(sorted(set(hosts))) + " - a Hermes default port; may be another program",
                    fix="Start it with --host 127.0.0.1 (or the matching *_HOST setting), or firewall the port. "
                        "If you need remote access, put a sign-in or tunnel in front.")
    else:
        rep.notes.append("Could not list listening ports (no ss/lsof); live exposure check skipped.")

    # --- files at rest
    common.check_permissions(rep, [hh, hh / ".env", cfg_path], "medium")
    common.check_permissions(rep, [hh / n for n in CREDENTIAL_FILES], "high")
    common.scan_secrets(rep, cfg_path, "medium", "Plain-text credential in config.yaml",
                        "Move it to ~/.hermes/.env (chmod 600) and rotate the key.")
    mem_dirs = [hh / "memories"] + sorted((hh / "profiles").glob("*/memories")) if (hh / "profiles").is_dir() else [hh / "memories"]
    for d in mem_dirs:
        for md in sorted(d.glob("*.md")) if d.is_dir() else []:
            common.scan_secrets(rep, md, "high", "Credential in an agent memory file",
                                "Delete the entry and rotate the key; the agent can read and repeat memory.")

    # --- skills, hooks
    roots = [hh / "skills", home / ".agents" / "skills"]
    ext = dig(cfg, "skills", "external_dirs", default=[]) or []
    roots += [common.expand(str(x), home) for x in ext if isinstance(x, str)]
    n = common.review_dirs(rep, "Skill", roots)
    rep.notes.append(f"Reviewed {n} skill(s) under {len([r for r in roots if r.is_dir()])} directories "
                     "(bundled skills are included; Hermes also scans hub installs itself).")
    quarantine = hh / "skills" / ".hub" / "quarantine"
    if quarantine.is_dir() and any(quarantine.iterdir()):
        rep.add("info", "skills", "Hermes has quarantined skills awaiting your decision", path=str(quarantine),
                fix="Review them with the hub commands, or delete the entries.")
    hooks = hh / "hooks"
    if hooks.is_dir():
        for hd in sorted(p for p in hooks.iterdir() if p.is_dir()):
            rep.add("low", "hooks", f"Hook '{hd.name}' runs Python in the gateway process", path=str(hd),
                    fix="Keep only hooks you wrote or reviewed.")
            common.review_tree(rep, "Hook", hd)
    return rep
