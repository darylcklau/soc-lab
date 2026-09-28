import docker
import logging

logger = logging.getLogger(__name__)


def get_container_status() -> dict:
    """
    Returns a dict of {container_name: status} for all running
    and stopped containers on the local Docker host.
    """
    try:
        client = docker.from_env()
        containers = client.containers.list(all=True)
        result = {}
        for c in containers:
            result[c.name] = c.status
        return result
    except Exception as e:
        logger.error(f"Docker health check failed: {e}")
        return {"error": str(e)}


def get_alerts_json_size() -> int | None:
    """
    alerts.json lives on the server laptop (Wazuh manager), not the Pi.
    Returns None — divergence check uses indexer count only.
    """
    return None
