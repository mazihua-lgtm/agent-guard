# agent-guard

Read-only security audit for personal AI agents running on **your own machine**. v0.1 covers
[OpenClaw](https://github.com/openclaw/openclaw) and [Hermes Agent](https://hermes-agent.nousresearch.com).

只读体检工具：检查你本机上的个人 AI 智能体（OpenClaw、Hermes Agent）有没有暴露在网络上、有没有明文密钥、装的 skill 有没有危险写法。不改任何文件，不联网，零依赖。

## What it checks

| Area | Examples |
|---|---|
| Exposure | gateway/API server bound to `0.0.0.0`, auth disabled, Tailscale Funnel, default ports listening on a non-loopback address, wildcard CORS |
| Access and approvals | Hermes `*_ALLOW_ALL_USERS`, `approvals.mode: off`, `HERMES_YOLO_MODE`, auto-approve in cron/unattended mode, OpenClaw sandbox off |
| Secrets | API keys, tokens, private keys in config files and agent memory; loose permissions on `.env`, `auth.json`, token stores (values are always masked) |
| Skills, plugins, hooks | `curl \| sh`, base64-decode-and-exec, reverse shells, reading `~/.ssh` or agent credentials while sending data out, exfil endpoints, shell-profile/cron persistence, prompt-injection wording |

Every rule is traceable to vendor documentation: see [docs/SOURCES.md](docs/SOURCES.md).

## Use

```sh
git clone https://github.com/mazihua-lgtm/agent-guard && cd agent-guard
python3 -m agent_guard                          # terminal summary
python3 -m agent_guard --format markdown -o report.md
python3 -m agent_guard --format json --fail-on high   # exit 1 if any high/critical finding
python3 -m agent_guard --agent hermes --min-severity medium --no-network
```

Python 3.9+. PyYAML is used when installed, otherwise a built-in reader handles the config subset it needs.

## What it does not do

- It never writes, moves or deletes anything, and never executes skill code. It reads files and runs `lsof`/`ss` once to list listening ports.
- Static pattern matching finds common bad patterns; it cannot prove a skill is safe. Findings in documentation files are downgraded because they are usually instructions to the reader.
- It does not replace `openclaw doctor` / `openclaw security audit` or `hermes doctor`; it works across agents and looks at the host.
- Bundled skills are scanned too, so expect a few low-severity notes from vendor docs.

## Tests

```sh
python3 -m unittest discover -s tests -t .
```

MIT licensed.
