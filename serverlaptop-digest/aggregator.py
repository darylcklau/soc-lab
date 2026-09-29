#!/usr/bin/env python3
"""
SOC digest aggregator.

Unifies the per-sensor JSON pushed into /var/log/soc-aggregated/{role}/
with Wazuh's local alert log into a single soc-aggregated/v1 dict.

Library entry point: aggregate() -> dict.
When run directly, pretty-prints the dict as JSON for inspection.
"""
from __future__ import annotations

import gzip
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA_VERSION = "soc-aggregated/v1"
AGGREGATION_ROOT = Path("/var/log/soc-aggregated")
WAZUH_ALERTS_DIR = Path("/var/ossec/logs/alerts")
WAZUH_CURRENT    = WAZUH_ALERTS_DIR / "alerts.json"
SENSOR_ROLES     = ("pi4",)
STALE_THRESHOLD_SECONDS = 90 * 60  # 90 min — push is at 08:50 SGT, report at 09:00 SGT
INTERNAL_CIDRS   = ["10.0.0.0/24"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_wazuh_ts(s: str) -> datetime | None:
    """Wazuh writes timestamps like '2026-05-11T00:00:03.406+0000'."""
    if not s:
        return None
    # Normalize +0000 → +00:00 so fromisoformat accepts it.
    if len(s) >= 5 and (s.endswith("+0000") or s.endswith("-0000")):
        s = s[:-5] + s[-5:-2] + ":" + s[-2:]
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Sensor JSON loading
# ---------------------------------------------------------------------------

def load_sensor(role: str, now_utc: datetime) -> dict:
    """Read /var/log/soc-aggregated/<role>/<role>-current.json with staleness check."""
    path = AGGREGATION_ROOT / role / f"{role}-current.json"
    if not path.exists():
        return {
            "fresh": False,
            "last_push_utc": None,
            "age_seconds": None,
            "data": None,
            "stale_reason": f"no pushed file at {path}",
        }
    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    age = (now_utc - mtime).total_seconds()
    fresh = age <= STALE_THRESHOLD_SECONDS
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        return {
            "fresh": False,
            "last_push_utc": mtime.isoformat(),
            "age_seconds": age,
            "data": None,
            "stale_reason": f"could not parse JSON: {e}",
        }
    return {
        "fresh": fresh,
        "last_push_utc": mtime.isoformat(),
        "age_seconds": age,
        "data": data,
        "stale_reason": (
            None if fresh
            else f"no push in last {age / 3600:.1f}h (threshold {STALE_THRESHOLD_SECONDS // 60} min)"
        ),
    }


# ---------------------------------------------------------------------------
# Wazuh local alert log
# ---------------------------------------------------------------------------

def _iter_wazuh_alert_files(window_start_utc: datetime,
                            window_end_utc: datetime,
                            now_utc: datetime):
    """Yield alert file paths covering the window, avoiding double-reads.

    alerts.json is hardlinked to today's archive (ossec-alerts-<DD>.json), so we
    treat today specially: read alerts.json once, read archives only for prior
    days.
    """
    today_utc = now_utc.date()
    day = window_start_utc.date()
    end_day = window_end_utc.date()
    while day <= end_day:
        if day == today_utc:
            if WAZUH_CURRENT.exists():
                yield WAZUH_CURRENT
        else:
            base = WAZUH_ALERTS_DIR / day.strftime("%Y") / day.strftime("%b")
            dd = day.strftime("%d")
            for fname in (f"ossec-alerts-{dd}.json", f"ossec-alerts-{dd}.json.gz"):
                p = base / fname
                if p.exists():
                    yield p
                    break
        day += timedelta(days=1)


def _open_alert_file(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def load_wazuh_alerts(window_start_utc: datetime,
                      window_end_utc: datetime,
                      now_utc: datetime):
    """Yield Wazuh alert dicts whose timestamp falls in the window."""
    for path in _iter_wazuh_alert_files(window_start_utc, window_end_utc, now_utc):
        try:
            fh = _open_alert_file(path)
        except (OSError, PermissionError):
            continue
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts_dt = _parse_wazuh_ts(alert.get("timestamp", ""))
                if ts_dt is None:
                    continue
                if window_start_utc <= ts_dt <= window_end_utc:
                    yield alert


def summarize_wazuh(alerts) -> dict:
    by_level       = Counter()
    rule_descs     = {}
    rule_counter   = Counter()
    src_ip_counter = Counter()
    mitre_counter  = Counter()
    by_hour        = Counter()
    total = 0

    for a in alerts:
        total += 1
        rule = a.get("rule") or {}
        level = rule.get("level")
        if level is not None:
            by_level[str(level)] += 1
        rid = rule.get("id")
        if rid:
            rule_counter[rid] += 1
            rule_descs.setdefault(rid, rule.get("description") or f"Rule {rid}")
        src_ip = (a.get("data") or {}).get("srcip") or ""
        if src_ip:
            src_ip_counter[src_ip] += 1
        for tactic in (rule.get("mitre") or {}).get("tactic", []) or []:
            mitre_counter[tactic] += 1
        ts = a.get("timestamp", "")
        if len(ts) >= 13 and "T" in ts:
            by_hour[ts[11:13]] += 1

    return {
        "available": True,
        "total_alerts": total,
        "by_level": dict(sorted(by_level.items(), key=lambda kv: int(kv[0]))),
        "top_rules": [
            {"id": rid, "description": rule_descs[rid], "count": c}
            for rid, c in rule_counter.most_common(10)
        ],
        "top_src_ips": [{"ip": ip, "count": c} for ip, c in src_ip_counter.most_common(10)],
        "top_mitre":   [{"tactic": t, "count": c} for t, c in mitre_counter.most_common(10)],
        "alerts_by_hour": dict(sorted(by_hour.items())),
    }


# ---------------------------------------------------------------------------
# Main aggregate entrypoint
# ---------------------------------------------------------------------------

def aggregate(now_utc: datetime | None = None, window_hours: int = 24) -> dict:
    if now_utc is None:
        now_utc = _utc_now()
    window_end = now_utc
    window_start = window_end - timedelta(hours=window_hours)

    sensors = {role: load_sensor(role, now_utc) for role in SENSOR_ROLES}

    try:
        wazuh = summarize_wazuh(load_wazuh_alerts(window_start, window_end, now_utc))
    except Exception as e:
        wazuh = {"available": False, "error": f"{type(e).__name__}: {e}"}

    return {
        "schema": SCHEMA_VERSION,
        "generated_at_utc":  now_utc.isoformat(),
        "window_start_utc":  window_start.isoformat(),
        "window_end_utc":    window_end.isoformat(),
        "sensors": sensors,
        "wazuh":   wazuh,
        "internal_cidrs": INTERNAL_CIDRS,
    }


def main():
    state = aggregate()
    print(json.dumps(state, indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
