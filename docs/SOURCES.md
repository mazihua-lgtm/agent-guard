# Where every rule comes from

agent-guard only checks paths, keys and defaults that the vendors document. Anything not listed here is not checked.
Docs were read on 2026-11-09; the agents change quickly, so re-verify before trusting an old rule.

## Hermes Agent (hermes-agent.nousresearch.com/docs)

| Rule | Source page / fact |
|---|---|
| Home `~/.hermes` or `HERMES_HOME`; `config.yaml`, `.env`, `memories/`, `skills/`, `hooks/`, `pairing/` | User guide: security, messaging, features/memory, features/skills |
| `*_ALLOW_ALL_USERS`, `gateway.allow_all_users` | Messaging: gateway is deny-all by default; allow-all is "not recommended" with terminal access |
| `approvals.mode` (`off` = `--yolo`), `HERMES_YOLO_MODE`, `cron_mode` / `single_query_mode` / `unattended_mode` (default `deny`) | Security: approvals |
| `security.allow_private_urls`, `security.allow_lazy_installs` | Security |
| API server: `API_SERVER_ENABLED`, `_HOST` (default `127.0.0.1`), `_PORT` (default `8642`), `_KEY`, `_CORS_ORIGINS` | Environment variable reference |
| Webhook: `WEBHOOK_ENABLED`, `WEBHOOK_PORT` (default `8644`), `WEBHOOK_SECRET` | Environment variable reference |
| Dashboard `9119`, Webapp `webapp.host` / `webapp.port` (default `9120`) | Dashboard and Webapp configuration |
| Credential files (`auth.json`, `.anthropic_oauth.json`, `google_token.json`, `vault/`, `mcp-tokens/`, ...) | Security: credential files |

## OpenClaw (docs.openclaw.ai, repo openclaw/openclaw)

| Rule | Source |
|---|---|
| Config `~/.openclaw/openclaw.json` (JSON5), `OPENCLAW_STATE_DIR`, `OPENCLAW_CONFIG_PATH`, `~/.openclaw/.env` | docs/gateway/configuration.md, .env.example |
| `gateway.bind` = `auto` / `loopback` (default) / `lan` (0.0.0.0) / `tailnet` / `custom`; container default `auto` | docs/gateway/config-gateway.md |
| `gateway.port` default `18789` | docs/gateway/config-gateway.md |
| `gateway.auth.mode` = `none` / `token` / `password` / `trusted-proxy`; non-loopback needs auth | docs/gateway/config-gateway.md, SECURITY.md |
| `gateway.tailscale.mode` = `funnel` is public | docs/gateway/config-gateway.md |
| `gateway.controlUi.allowExternalEmbedUrls`, `dangerouslyAllowHostHeaderOriginFallback`, `gateway.terminal.enabled`, `gateway.allowRealIpFallback`, `gateway.nodes.pairing.autoApproveCidrs` | docs/gateway/config-gateway.md |
| `agents.defaults.sandbox.mode` defaults to `off` | SECURITY.md |
| Skill roots: `<workspace>/skills`, `<workspace>/.agents/skills`, `~/.agents/skills`, `<state-dir>/skills`, `skills.load.extraDirs`; `plugins.load.paths` | docs/tools/skills.md, docs/tools/plugin.md |

## Not covered on purpose

- Channel allowlists / DM policy for OpenClaw: `openclaw doctor` and `openclaw security audit` own that; their key names were not verified here.
- Hermes per-route webhook secrets and the `allow_admin_from` split.
- Anything inside Docker/remote hosts: agent-guard reads the local machine only.
