#!/usr/bin/env python3
"""Standalone LLM alert-triage prototype — level>=7 Wazuh alerts -> Claude classification.

Not wired into daily_digest.py. Run directly to inspect output against real
alert data before deciding whether/how to wire it into the digest.
"""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from anthropic import Anthropic, APIConnectionError, APIStatusError
from dotenv import load_dotenv

from aggregator import _utc_now, load_wazuh_alerts

load_dotenv(Path(__file__).parent / ".env")

MODEL = "claude-opus-5"

KNOWN_NOISE_BASELINES = """\
- Rule 550 firmware FIM bursts on /boot/firmware/* — Pi 4, baseline noise
- Rule 60110 user account changed — LAUMAINDESK$ SYSTEM paired ms-apart bursts = Windows Hello credential refresh, benign
- Rule 60122 logon failure — 127.0.0.1, blank usernames = local lock-screen PIN mistype, benign
- LauMainDesk Registry FIM under HKLM\\System\\CurrentControlSet\\Services — full-tree scan noise, accepted as-is (rule 61138 covers real persistence)
- Rules 100010 (auto-block of high-abuse-score scanner), 100200 (Cowrie honeypot credential capture / login success), 100020 (Cowrie brute-force detection) on Pi4 — the honeypot and threat-monitor doing their designed job against internet scanners, expected daily volume, benign
- Rule 100030 (port-scan detection on Pi4 by the threat-monitor) when the scanning source is an external/internet IP — routine internet background scanning against the honeypot host, expected daily volume, benign. A scan originating from an internal 192.168.50.x address is NOT covered and stays novel
- Rule 100070 (Cowrie brute-force threshold on Pi4, N failed attempts from one IP) — the honeypot threat-monitor doing its designed job against internet scanners, expected daily volume, benign
- Rule 553 (file deleted) ONLY when the path is an old kernel/initrd/System.map file under /boot removed by a kernel package upgrade, or a snap mount unit — routine apt/snap cleanup, benign. A rule 553 deletion of anything else (logs, binaries, user files, config) is NOT covered and stays novel
- Rules 2902/2903/2904 (dpkg package install/remove/half-configured state) and the rule 550 FIM changes they trigger for binaries/config touched by the same upgrade — routine apt/unattended-upgrades package churn on any agent, benign
"""

SYSTEM_PROMPT = f"""You are a SOC alert triage assistant. You are given a batch of Wazuh alerts \
(level >=7) from a home security lab. Classify each alert as either \
"known_noise" (matches an established baseline below) or "novel" (does not \
match any baseline and warrants human review).

Established baselines:
{KNOWN_NOISE_BASELINES}
Classify every alert in the input — the output items array must have exactly \
one entry per input alert, in any order. For each, output alert_id (copied \
exactly, character-for-character, from that alert's "alert_id" field), \
rule_id, agent, verdict, and a one-sentence reason. Do not recommend or \
imply any remediation action. If uncertain, classify as "novel" — false \
negatives here mean a human misses something; false positives just mean one \
extra line in the digest."""

OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "items": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "alert_id": {"type": "string"},
                    "rule_id": {"type": "string"},
                    "agent": {"type": "string"},
                    "verdict": {"type": "string", "enum": ["known_noise", "novel"]},
                    "reason": {"type": "string"},
                },
                "required": ["alert_id", "rule_id", "agent", "verdict", "reason"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["items"],
    "additionalProperties": False,
}


def _strip_alert(alert: dict) -> dict:
    rule = alert.get("rule") or {}
    data = alert.get("data") or {}
    stripped = {
        "alert_id": alert.get("id"),
        "rule_id": rule.get("id"),
        "description": rule.get("description"),
        "level": rule.get("level"),
        "agent": (alert.get("agent") or {}).get("name"),
        "full_log": (alert.get("full_log") or "")[:500],
    }
    syscheck_path = (alert.get("syscheck") or {}).get("path")
    if syscheck_path:
        stripped["syscheck_path"] = syscheck_path
    win_eventdata = (data.get("win") or {}).get("eventdata")
    if win_eventdata:
        stripped["win_eventdata"] = win_eventdata
    return stripped


def triage_alerts(alerts: list[dict]) -> dict:
    """Batch-classify level>=7 alerts via one Claude call. Advisory only — text/JSON output."""
    generated_at = _utc_now().isoformat()
    if not alerts:
        return {"generated_at": generated_at, "model": MODEL,
                "novel_count": 0, "suppressed_count": 0, "items": []}

    client = Anthropic()
    try:
        with client.messages.stream(
            model=MODEL,
            max_tokens=64000,
            system=SYSTEM_PROMPT,
            output_config={"effort": "low", "format": {"type": "json_schema", "schema": OUTPUT_SCHEMA}},
            messages=[{"role": "user", "content": json.dumps([_strip_alert(a) for a in alerts])}],
        ) as stream:
            response = stream.get_final_message()
    except (APIStatusError, APIConnectionError) as e:
        body = getattr(e, "body", None)
        msg = (body.get("error", {}).get("message") if isinstance(body, dict) else None) or str(e)
        return {"generated_at": generated_at, "model": MODEL,
                "status": "unavailable", "error": f"{type(e).__name__}: {msg}"}

    if response.stop_reason == "max_tokens":
        return {"generated_at": generated_at, "model": MODEL,
                "status": "unavailable", "error": "response truncated at max_tokens"}

    text = next(b.text for b in response.content if b.type == "text")
    items = json.loads(text)["items"]

    sent_ids = {a.get("id") for a in alerts}
    returned_ids = {i["alert_id"] for i in items}
    dropped = sent_ids - returned_ids
    if dropped:
        # Model silently omitted alerts rather than misclassifying them — surface
        # this as unavailable rather than presenting an undercount as complete.
        return {"generated_at": generated_at, "model": MODEL,
                "status": "unavailable",
                "error": f"model returned {len(items)}/{len(alerts)} alerts; "
                         f"{len(dropped)} dropped: {sorted(dropped)[:10]}"}

    novel = sum(1 for i in items if i["verdict"] == "novel")
    return {
        "generated_at": generated_at,
        "model": MODEL,
        "novel_count": novel,
        "suppressed_count": len(items) - novel,
        "items": items,
    }


def _add_groups(result: dict, alerts: list[dict]) -> None:
    """Group novel items by (rule, agent) with the rule description for the digest."""
    desc = {a.get("id"): (a.get("rule") or {}).get("description", "") for a in alerts}
    groups: dict = {}
    for i in result.get("items", []):
        if i["verdict"] != "novel":
            continue
        g = groups.setdefault((i["rule_id"], i["agent"]), {
            "rule_id": i["rule_id"], "agent": i["agent"], "count": 0,
            "description": desc.get(i["alert_id"], ""), "reason": i["reason"]})
        g["count"] += 1
    result["groups"] = sorted(groups.values(), key=lambda g: -g["count"])


def main():
    now = _utc_now()
    window_start = now - timedelta(hours=24)
    alerts = [a for a in load_wazuh_alerts(window_start, now, now)
              if (a.get("rule") or {}).get("level", 0) >= 7]
    print(f"[info] {len(alerts)} level>=7 alerts in the last 24h", file=__import__("sys").stderr)
    result = triage_alerts(alerts)
    _add_groups(result, alerts)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
