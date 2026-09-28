import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone
import config
from connectors.wazuh import get_recent_alerts, get_agent_status
from connectors.cowrie import get_recent_sessions, get_top_attackers
from connectors.threat_monitor import get_blocked_ips
from connectors.opencti import get_recent_reports, get_observable_count
from connectors.docker_health import get_container_status

logger = logging.getLogger(__name__)


def _section(title: str, rows: list) -> str:
    """Render an HTML table section."""
    if not rows:
        return f"<h3>{title}</h3><p>None.</p>"
    header = "".join(f"<th>{k}</th>" for k in rows[0].keys())
    body = ""
    for row in rows:
        cells = "".join(f"<td>{v}</td>" for v in row.values())
        body += f"<tr>{cells}</tr>"
    return (
        f"<h3>{title}</h3>"
        f"<table border='1' cellpadding='4' cellspacing='0' style='border-collapse:collapse'>"
        f"<tr>{header}</tr>{body}</table>"
    )


def build_html_report() -> str:
    """Assemble the full HTML email body."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    parts = [
        f"<html><body>",
        f"<h2>SOC Daily Report — {now_str}</h2>",
    ]

    # Wazuh alerts level 10+
    try:
        alerts = get_recent_alerts(hours=24, min_level=10)
        rows = [
            {
                "Time": a["timestamp"][:19],
                "Level": a["level"],
                "Agent": a["agent"],
                "Src IP": a.get("src_ip", "N/A"),
                "Description": a["description"],
            }
            for a in alerts
        ]
        parts.append(_section(f"Wazuh Alerts — Level 10+ ({len(alerts)})", rows))
    except Exception as e:
        parts.append(f"<h3>Wazuh Alerts</h3><p>ERROR: {e}</p>")

    # Cowrie sessions
    try:
        sessions = get_recent_sessions(hours=24)
        top = get_top_attackers(hours=24, top_n=20)
        unique_ips = len(set(s["src_ip"] for s in sessions))
        parts.append(
            f"<h3>Cowrie Honeypot — {len(sessions)} sessions from {unique_ips} unique IPs</h3>"
        )
        attacker_rows = [{"IP": t["ip"], "Attempts": t["count"]} for t in top]
        parts.append(_section("Top Attackers", attacker_rows))

        # Sample of sessions with commands
        cmd_sessions = [s for s in sessions if s.get("input")][:20]
        cmd_rows = [
            {
                "Time": s["timestamp"][:19],
                "IP": s["src_ip"],
                "User": s.get("username", ""),
                "Command": s["input"][:80],
            }
            for s in cmd_sessions
        ]
        parts.append(_section("Command Attempts (sample)", cmd_rows))
    except Exception as e:
        parts.append(f"<h3>Cowrie</h3><p>ERROR: {e}</p>")

    # Blocked IPs
    try:
        blocked = get_blocked_ips()
        rows = [{"IP": ip} for ip in blocked]
        parts.append(_section(f"Blocked IPs on Pi 4 ({len(blocked)})", rows))
    except Exception as e:
        parts.append(f"<h3>Blocked IPs</h3><p>ERROR: {e}</p>")

    # OpenCTI
    try:
        reports = get_recent_reports(limit=10)
        ioc_count = get_observable_count()
        parts.append(f"<h3>OpenCTI — {ioc_count} total IOCs</h3>")
        rows = [
            {
                "Created": r["created_at"][:19],
                "Name": r["name"],
                "Description": (r.get("description") or "")[:100],
            }
            for r in reports
        ]
        parts.append(_section("Recent Reports", rows))
    except Exception as e:
        parts.append(f"<h3>OpenCTI</h3><p>ERROR: {e}</p>")

    # Docker health
    try:
        containers = get_container_status()
        rows = [
            {
                "Container": name,
                "Status": status,
                "OK": "✅" if status == "running" else "❌",
            }
            for name, status in sorted(containers.items()) if name in config.MONITORED_CONTAINERS
        ]
        parts.append(_section("Docker Container Health", rows))
    except Exception as e:
        parts.append(f"<h3>Docker</h3><p>ERROR: {e}</p>")

    # Wazuh agents
    try:
        agents = get_agent_status()
        rows = [
            {
                "Name": a["name"],
                "IP": a["ip"],
                "Status": a["status"],
                "Last Keepalive": a.get("last_keepalive", "N/A"),
                "OK": "✅" if a["status"] == "active" else "❌",
            }
            for a in agents
        ]
        parts.append(_section("Wazuh Agent Status", rows))
    except Exception as e:
        parts.append(f"<h3>Wazuh Agents</h3><p>ERROR: {e}</p>")

    parts.append("</body></html>")
    return "".join(parts)


def send_daily_email():
    """Build and send the daily HTML report via Gmail SMTP."""
    try:
        html_body = build_html_report()
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"SOC Daily Report — {date_str}"
        msg["From"] = config.SMTP_USER
        msg["To"] = config.EMAIL_RECIPIENT
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.login(config.SMTP_USER, config.SMTP_PASS)
            server.sendmail(config.SMTP_USER, config.EMAIL_RECIPIENT, msg.as_string())

        logger.info(f"Daily email sent to {config.EMAIL_RECIPIENT}")

    except Exception as e:
        logger.error(f"Failed to send daily email: {e}")
        raise
