import json
import logging
from datetime import datetime, timedelta

LOGIN_EVENTS = {"cowrie.login.failed", "cowrie.login.success"}
COWRIE_LOG = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"

logger = logging.getLogger(__name__)


def get_recent_sessions(hours: int = 24) -> list:
    """
    Returns Cowrie sessions from the last N hours.
    Reads cowrie.json log directly from local filesystem.
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    sessions = []
    try:
        with open(COWRIE_LOG, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    ts_str = entry.get("timestamp", "")[:19]
                    ts = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")
                    if ts < cutoff:
                        continue
                    sessions.append({
                        "timestamp": entry.get("timestamp", ""),
                        "event":     entry.get("eventid", ""),
                        "src_ip":    entry.get("src_ip", "N/A"),
                        "username":  entry.get("username", ""),
                        "password":  entry.get("password", ""),
                        "input":     entry.get("input", ""),
                        "session":   entry.get("session", "")
                    })
                except (json.JSONDecodeError, ValueError):
                    continue
    except Exception as e:
        logger.error(f"Cowrie session fetch failed: {e}")
    return sessions


def get_top_attackers(hours: int = 24, top_n: int = 10) -> list:
    """
    Returns top N attacker IPs by login attempt count in the last N hours.
    Only counts cowrie.login.failed / cowrie.login.success events.
    """
    sessions = get_recent_sessions(hours=hours)
    counts = {}
    for s in sessions:
        if s["event"] not in LOGIN_EVENTS:
            continue
        ip = s["src_ip"]
        counts[ip] = counts.get(ip, 0) + 1
    sorted_ips = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    return [{"ip": ip, "count": count} for ip, count in sorted_ips[:top_n]]
