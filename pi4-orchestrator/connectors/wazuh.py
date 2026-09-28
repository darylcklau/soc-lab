import requests
import logging
import urllib3
from datetime import datetime, timedelta
import config

# Wazuh uses a self-signed cert — suppress warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

WAZUH_BASE = f"https://{config.WAZUH_HOST}:{config.WAZUH_PORT}"


def _get_token() -> str:
    """Authenticate and return a JWT token."""
    resp = requests.post(
        f"{WAZUH_BASE}/security/user/authenticate",
        auth=(config.WAZUH_USER, config.WAZUH_PASS),
        verify=False,
        timeout=10
    )
    resp.raise_for_status()
    return resp.json()["data"]["token"]


def get_agent_status() -> list:
    """
    Returns a list of dicts with agent name, ID, IP, and status.
    """
    try:
        token = _get_token()
        resp = requests.get(
            f"{WAZUH_BASE}/agents",
            headers={"Authorization": f"Bearer {token}"},
            params={"limit": 50},
            verify=False,
            timeout=10
        )
        resp.raise_for_status()
        agents = resp.json()["data"]["affected_items"]
        return [
            {
                "id": a["id"],
                "name": a["name"],
                "ip": a.get("ip", "N/A"),
                "status": a["status"],
                "last_keepalive": a.get("lastKeepAlive", "N/A")
            }
            for a in agents
        ]
    except Exception as e:
        logger.error(f"Wazuh agent status failed: {e}")
        return []


def get_recent_alerts(hours: int = 24, min_level: int = 10) -> list:
    """
    Returns alerts from the last N hours at or above min_level.
    Queries the Wazuh indexer (OpenSearch) directly.
    """
    try:
        since = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        query = {
            "size": 500,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": min_level}}},
                        {"range": {"@timestamp": {"gte": since}}}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        resp = requests.post(
            f"{config.WAZUH_INDEXER_URL}/wazuh-alerts-*/_search",
            json=query,
            auth=(config.WAZUH_INDEXER_USER, config.WAZUH_INDEXER_PASS),
            verify=False,
            timeout=15
        )
        resp.raise_for_status()
        hits = resp.json()["hits"]["hits"]
        return [
            {
                "id": h["_id"],
                "level": h["_source"]["rule"]["level"],
                "description": h["_source"]["rule"]["description"],
                "src_ip": h["_source"].get("data", {}).get("srcip", "N/A"),
                "agent": h["_source"]["agent"]["name"],
                "timestamp": h["_source"]["@timestamp"]
            }
            for h in hits
        ]
    except Exception as e:
        logger.error(f"Wazuh alert fetch failed: {e}")
        return []


def get_indexer_doc_count(hours: int = 1) -> int | None:
    """
    Returns the number of alert documents indexed in the last N hours.
    Used to detect filebeat silent failures: if alerts.json grows but
    this count stagnates, filebeat is not shipping to the indexer.
    Returns None on error.
    """
    try:
        since = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        query = {
            "query": {
                "range": {
                    "@timestamp": {"gte": since}
                }
            }
        }
        resp = requests.post(
            f"{config.WAZUH_INDEXER_URL}/wazuh-alerts-*/_count",
            json=query,
            auth=(config.WAZUH_INDEXER_USER, config.WAZUH_INDEXER_PASS),
            verify=False,
            timeout=10
        )
        resp.raise_for_status()
        return resp.json()["count"]
    except Exception as e:
        logger.error(f"Wazuh indexer doc count failed: {e}")
        return None


def _normalize(h: dict) -> dict:
    s = h["_source"]
    rule, data = s.get("rule") or {}, s.get("data") or {}
    return {
        "alert_id": h["_id"],
        "rule_id": str(rule.get("id", "")),
        "description": rule.get("description", ""),
        "level": rule.get("level", 0),
        "agent": (s.get("agent") or {}).get("name", "N/A"),
        "src_ip": data.get("srcip", "N/A"),
        "full_log": (s.get("full_log") or "")[:500],
        "syscheck_path": (s.get("syscheck") or {}).get("path", ""),
        "win_eventdata": (data.get("win") or {}).get("eventdata"),
        "timestamp": s.get("@timestamp", ""),
    }


def _search(must: list, size: int, order: str) -> list:
    resp = requests.post(
        f"{config.WAZUH_INDEXER_URL}/wazuh-alerts-*/_search",
        json={"size": size, "query": {"bool": {"must": must}},
              "sort": [{"@timestamp": {"order": order}}]},
        auth=(config.WAZUH_INDEXER_USER, config.WAZUH_INDEXER_PASS),
        verify=False,
        timeout=15,
    )
    resp.raise_for_status()
    return [_normalize(h) for h in resp.json()["hits"]["hits"]]


def get_alerts_between(minutes: int, min_level: int, max_level: int) -> list:
    """Alerts with full context fields for L1 triage. Raises on failure (caller decides)."""
    since = (datetime.utcnow() - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return _search([
        {"range": {"rule.level": {"gte": min_level, "lte": max_level}}},
        {"range": {"@timestamp": {"gte": since}}},
    ], size=500, order="asc")


def get_related_alerts(src_ip: str, agent: str, hours: int = 6) -> list:
    """Recent alerts for the same source IP (or same agent when no IP). Raises on failure."""
    since = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    who = {"term": {"data.srcip": src_ip}} if src_ip not in ("", "N/A", "localhost") \
        else {"term": {"agent.name": agent}}
    return _search([who, {"range": {"@timestamp": {"gte": since}}}], size=100, order="desc")
