# soc-lab

Home security lab automation: a Wazuh-based SOC with a Telegram bot, a daily email digest, and LLM-assisted alert triage. Advisory only: the model never blocks, restarts or changes anything.

## Components

**`pi4-orchestrator/`** (Raspberry Pi 4, runs the Cowrie honeypot, Zeek and a threat-monitor)
- APScheduler jobs: health checks, Wazuh alert polling (level >= 12), Cowrie persistence checks, Telegram bot (`/status /digest /threats /block`).
- `analysis/l1_triage.py`: **L1-analyst triage, currently in shadow mode.** Every 30 min it takes level 7-11 alerts, drops known-benign baselines in code, and asks Claude to classify the rest as `noise` / `watch` / `investigate`. It also annotates alerts the poll job already escalated. Results are only written to `logs/l1_shadow.jsonl`; nothing is sent to Telegram yet.

- `analysis/honeypot_investigator.py`: **honeypot specialist (on demand).** `python -m analysis.honeypot_investigator <ip> ["why flagged"]` runs an L2-style investigation of one Cowrie source IP. The model chooses its own read-only queries (session history, transcripts, shared-indicator pivots for campaign linking, Wazuh alerts, actor history) within a 12-turn budget and must finish with a structured case (classification, severity, confidence, timeline, evidence, human-decides actions), saved to `cases/honeypot/`. Not scheduled and not wired to Telegram yet.

**`serverlaptop-digest/`** (Wazuh manager host, cron 01:00 UTC)
- `aggregator.py` builds the 24h state from Wazuh's local alert log and sensor pushes; `daily_digest.py` renders and emails it.
- `triage.py`: batches the last 24h of level >= 7 alerts into one Claude call and adds an "ALERT TRIAGE" section plus an `alert triage: OK/RED` health row to the digest. Failures never block the digest.

## Safety design
- The model has no tools and no write access; output is a fixed JSON schema.
- Alert text (logs, usernames, commands) is attacker-controlled, especially from the honeypot, so it is treated as untrusted data in the prompt.
- Every alert sent to the model must come back with an `alert_id`; omitted alerts are surfaced, never silently dropped.
- Level >= 12 escalations are annotated, never suppressed.
- Hard daily call cap and a timeout on every model call; kill switches `ENABLE_L1_TRIAGE=0` / `ENABLE_ALERT_TRIAGE=0`.

## Setup
1. Copy each `.env.example` to `.env` on the target host, fill it in, `chmod 600 .env`.
2. Create the Anthropic API key inside a workspace (unscoped keys are rejected).
3. Python: `pip install -r` equivalents are `anthropic python-dotenv apscheduler python-telegram-bot requests jinja2 pytz`.
4. Digest cron: `0 1 * * * .venv/bin/python daily_digest.py >> daily_digest.log 2>&1`.
5. Orchestrator runs as a systemd service; the Wazuh indexer is reached through an SSH tunnel on `127.0.0.1:19200`.

## Status
- Digest triage: live.
- L1 triage: shadow mode, being reviewed before enabling Telegram output.
- Model: `claude-opus-5` at low effort.

Do not commit `.env`, `state.db`, logs or `*.bak*` files (see `.gitignore`).
