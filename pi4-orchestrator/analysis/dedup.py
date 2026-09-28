import sqlite3
import logging
from datetime import datetime, timedelta
import config

logger = logging.getLogger(__name__)


def _conn():
    return sqlite3.connect(config.STATE_DB, timeout=10)


def _init_db(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS seen_alerts (
            rule_id     TEXT NOT NULL,
            src_ip      TEXT NOT NULL,
            first_seen  TEXT NOT NULL,
            last_seen   TEXT NOT NULL,
            PRIMARY KEY (rule_id, src_ip)
        );

        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip          TEXT PRIMARY KEY,
            blocked_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cowrie_actors (
            src_ip      TEXT NOT NULL,
            seen_date   TEXT NOT NULL,
            PRIMARY KEY (src_ip, seen_date)
        );
    """)
    conn.commit()


def is_duplicate_alert(rule_id: str, src_ip: str) -> bool:
    """
    Returns True if this rule+IP was already seen within DEDUP_WINDOW_HOURS.
    Records the event if it's new or the window has expired.
    """
    now = datetime.utcnow()
    window_start = now - timedelta(hours=config.DEDUP_WINDOW_HOURS)

    try:
        with _conn() as conn:
            _init_db(conn)
            row = conn.execute(
                "SELECT last_seen FROM seen_alerts WHERE rule_id=? AND src_ip=?",
                (rule_id, src_ip)
            ).fetchone()

            if row:
                last_seen = datetime.fromisoformat(row[0])
                if last_seen >= window_start:
                    return True
                # window expired — update timestamp
                conn.execute(
                    "UPDATE seen_alerts SET last_seen=? WHERE rule_id=? AND src_ip=?",
                    (now.isoformat(), rule_id, src_ip)
                )
            else:
                conn.execute(
                    "INSERT INTO seen_alerts (rule_id, src_ip, first_seen, last_seen) VALUES (?,?,?,?)",
                    (rule_id, src_ip, now.isoformat(), now.isoformat())
                )
            conn.commit()
            return False

    except Exception as e:
        logger.error(f"Dedup check failed: {e}")
        return False


def record_blocked_ip(ip: str):
    """Record that an IP has been blocked."""
    try:
        with _conn() as conn:
            _init_db(conn)
            conn.execute(
                "INSERT OR REPLACE INTO blocked_ips (ip, blocked_at) VALUES (?,?)",
                (ip, datetime.utcnow().isoformat())
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to record blocked IP {ip}: {e}")


def is_ip_blocked(ip: str) -> bool:
    """Check if an IP is already recorded as blocked."""
    try:
        with _conn() as conn:
            _init_db(conn)
            row = conn.execute(
                "SELECT 1 FROM blocked_ips WHERE ip=?", (ip,)
            ).fetchone()
            return row is not None
    except Exception as e:
        logger.error(f"Failed to check blocked IP {ip}: {e}")
        return False


def record_cowrie_actor(src_ip: str):
    """Record a Cowrie attacker IP with today's date."""
    today = datetime.utcnow().date().isoformat()
    try:
        with _conn() as conn:
            _init_db(conn)
            conn.execute(
                "INSERT OR IGNORE INTO cowrie_actors (src_ip, seen_date) VALUES (?,?)",
                (src_ip, today)
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to record Cowrie actor {src_ip}: {e}")


def get_cowrie_actor_history(days: int = 7) -> dict:
    """
    Returns {src_ip: [date_str, ...]} for the last N days.
    """
    cutoff = (datetime.utcnow().date() - timedelta(days=days)).isoformat()
    try:
        with _conn() as conn:
            _init_db(conn)
            rows = conn.execute(
                "SELECT src_ip, seen_date FROM cowrie_actors WHERE seen_date >= ?",
                (cutoff,)
            ).fetchall()
        history = {}
        for ip, date in rows:
            history.setdefault(ip, []).append(date)
        return history
    except Exception as e:
        logger.error(f"Failed to fetch Cowrie actor history: {e}")
        return {}
