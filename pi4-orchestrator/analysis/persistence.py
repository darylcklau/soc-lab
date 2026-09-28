import logging
from datetime import datetime, timedelta
import config
from analysis.dedup import get_cowrie_actor_history, record_cowrie_actor
from connectors.cowrie import get_recent_sessions

logger = logging.getLogger(__name__)


def check_persistent_attackers() -> list:
    """
    Compares today's Cowrie attacker IPs against a 7-day rolling history.
    Returns a list of alert dicts for any IP that reappears after a 24h+ gap.

    Side effect: records today's seen IPs into the SQLite history.
    """
    today = datetime.utcnow().date()
    yesterday = today - timedelta(days=1)

    # Fetch today's sessions and record them
    sessions = get_recent_sessions(hours=24)
    today_ips = set()
    for s in sessions:
        ip = s.get("src_ip", "")
        if ip and ip != "N/A":
            today_ips.add(ip)
            record_cowrie_actor(ip)

    # Load rolling history (last 7 days excluding today)
    history = get_cowrie_actor_history(days=config.COWRIE_PERSISTENCE_DAYS)

    persistent = []
    for ip in today_ips:
        past_dates = [d for d in history.get(ip, []) if d < today.isoformat()]
        if not past_dates:
            continue

        # Find the most recent past date for this IP
        most_recent = max(past_dates)
        most_recent_dt = datetime.fromisoformat(most_recent)
        gap = today - most_recent_dt.date()

        if gap.days >= 1:
            persistent.append({
                "type": "cowrie_persistence",
                "src_ip": ip,
                "last_seen": most_recent,
                "gap_days": gap.days,
                "past_appearances": sorted(past_dates),
                "timestamp": datetime.utcnow().isoformat(),
            })
            logger.warning(
                f"Persistent attacker detected: {ip} last seen {most_recent} ({gap.days}d gap)"
            )

    return persistent
