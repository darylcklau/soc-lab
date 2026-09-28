import logging
from datetime import datetime, timezone
import config
from analysis.dedup import is_duplicate_alert
from analysis.persistence import check_persistent_attackers
from connectors.wazuh import get_recent_alerts, get_agent_status
from connectors.cowrie import get_recent_sessions, get_top_attackers
from connectors.threat_monitor import get_blocked_ips, get_anomaly_summary
from connectors.opencti import get_recent_reports, get_observable_count
from connectors.docker_health import get_container_status

logger = logging.getLogger(__name__)


def get_escalated_alerts() -> list:
    """
    Pulls from all connectors and returns a list of structured alert dicts
    that meet escalation criteria:
      - Wazuh level >= WAZUH_ESCALATE_LEVEL (12)
      - Cowrie persistence hits (reappearing attacker)
      - Docker service down
      - Pi 3 auto-block triggered (new blocked IP since last check)
    Dedup is applied to Wazuh alerts only.
    """
    alerts = []
    now = datetime.now(timezone.utc).isoformat()

    # --- Wazuh high-level alerts ---
    try:
        wazuh_alerts = get_recent_alerts(hours=1, min_level=config.WAZUH_ESCALATE_LEVEL)
        for a in wazuh_alerts:
            rule_id = str(a.get("id", a.get("description", "unknown")))
            src_ip = a.get("src_ip", "N/A")
            if is_duplicate_alert(rule_id, src_ip):
                continue
            alerts.append({
                "type": "wazuh",
                "severity": "HIGH",
                "title": f"Wazuh Level {a['level']}: {a['description']}",
                "src_ip": src_ip,
                "agent": a.get("agent", "N/A"),
                "timestamp": a.get("timestamp", now),
                "raw": a,
            })
    except Exception as e:
        logger.error(f"Wazuh escalation check failed: {e}")

    # --- Cowrie persistence ---
    try:
        for hit in check_persistent_attackers():
            alerts.append({
                "type": "cowrie_persistence",
                "severity": "MEDIUM",
                "title": f"Persistent attacker: {hit['src_ip']} (gap {hit['gap_days']}d)",
                "src_ip": hit["src_ip"],
                "timestamp": hit["timestamp"],
                "raw": hit,
            })
    except Exception as e:
        logger.error(f"Persistence check failed: {e}")

    # --- Docker service down ---
    try:
        containers = get_container_status()
        for name, status in containers.items():
            if name in config.MONITORED_CONTAINERS and status != "running":
                alerts.append({
                    "type": "docker_down",
                    "severity": "HIGH",
                    "title": f"Container DOWN: {name}",
                    "src_ip": "localhost",
                    "timestamp": now,
                    "raw": {"container": name, "status": status},
                })
    except Exception as e:
        logger.error(f"Docker health escalation failed: {e}")

    # --- Pi 3 new blocked IPs ---
    try:
        blocked = get_blocked_ips()
        for ip in blocked:
            # We flag new blocks; dedup key uses a synthetic rule ID
            rule_id = f"pi3_block_{ip}"
            if not is_duplicate_alert(rule_id, ip):
                alerts.append({
                    "type": "pi3_block",
                    "severity": "MEDIUM",
                    "title": f"Pi 3 auto-blocked: {ip}",
                    "src_ip": ip,
                    "timestamp": now,
                    "raw": {"ip": ip},
                })
    except Exception as e:
        logger.error(f"Pi 3 block escalation failed: {e}")

    return alerts


def build_digest() -> str:
    """
    Returns a formatted 24h summary string suitable for Telegram HTML.
    """
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"<b>SOC Daily Digest — {now_str}</b>\n"]

    # Wazuh
    try:
        wazuh_alerts = get_recent_alerts(hours=24, min_level=10)
        lines.append(f"<b>Wazuh Alerts (level 10+):</b> {len(wazuh_alerts)}")
        for a in wazuh_alerts[:5]:
            lines.append(f"  [{a['level']}] {a['description']} — {a.get('src_ip', 'N/A')}")
        if len(wazuh_alerts) > 5:
            lines.append(f"  ...and {len(wazuh_alerts) - 5} more")
    except Exception as e:
        lines.append(f"  Wazuh: ERROR ({e})")

    # Cowrie
    try:
        sessions = get_recent_sessions(hours=24)
        top = get_top_attackers(hours=24, top_n=5)
        unique_ips = len(set(s["src_ip"] for s in sessions))
        lines.append(f"\n<b>Cowrie Sessions:</b> {len(sessions)} from {unique_ips} unique IPs")
        for t in top:
            lines.append(f"  {t['ip']}: {t['count']} login attempts")
    except Exception as e:
        lines.append(f"\nCowrie: ERROR ({e})")

    # Blocked IPs
    try:
        blocked = get_blocked_ips()
        lines.append(f"\n<b>Blocked IPs (Pi 4):</b> {len(blocked)}")
        for ip in blocked[:10]:
            lines.append(f"  {ip}")
        if len(blocked) > 10:
            lines.append(f"  ...and {len(blocked) - 10} more")
    except Exception as e:
        lines.append(f"\nBlocked IPs: ERROR ({e})")

    # OpenCTI
    try:
        reports = get_recent_reports(limit=5)
        ioc_count = get_observable_count()
        lines.append(f"\n<b>OpenCTI:</b> {ioc_count} IOCs | {len(reports)} recent reports")
        for r in reports[:3]:
            lines.append(f"  • {r['name']}")
    except Exception as e:
        lines.append(f"\nOpenCTI: ERROR ({e})")

    # Docker
    try:
        containers = get_container_status()
        down = [n for n, s in containers.items() if s != "running" and "error" not in n and n in config.MONITORED_CONTAINERS]
        up_count = len([s for s in containers.values() if s == "running"])
        lines.append(f"\n<b>Docker (Pi 4):</b> {up_count} up, {len(down)} down")
        for name in down:
            lines.append(f"  ❌ {name}: {containers[name]}")
    except Exception as e:
        lines.append(f"\nDocker: ERROR ({e})")

    # Wazuh agents
    try:
        agents = get_agent_status()
        inactive = [a for a in agents if a["status"] != "active" and a["name"] not in config.WAZUH_AGENT_WHITELIST]
        lines.append(f"\n<b>Wazuh Agents:</b> {len(agents)} total, {len(inactive)} inactive")
        for a in inactive:
            lines.append(f"  ❌ {a['name']} ({a['ip']}): {a['status']}")
    except Exception as e:
        lines.append(f"\nWazuh agents: ERROR ({e})")

    return "\n".join(lines)
