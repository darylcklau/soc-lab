import subprocess
import logging

logger = logging.getLogger(__name__)

THREAT_MONITOR_LOG = "/var/log/threat_monitor.log"


def _run_local(cmd: str) -> str:
    """Run a shell command locally and return stdout."""
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=10
    )
    return result.stdout


def get_blocked_ips() -> list:
    """
    Returns list of IPs currently blocked in iptables on Pi 4.
    """
    try:
        raw = _run_local("sudo iptables -L INPUT -n | grep DROP | awk '{print $4}'")
        ips = [ip.strip() for ip in raw.strip().split("\n") if ip.strip()]
        return ips
    except Exception as e:
        logger.error(f"Failed to get blocked IPs: {e}")
        return []


def get_anomaly_summary() -> dict:
    """
    Returns recent anomaly detection summary from local threat monitor log.
    """
    try:
        raw = _run_local(f"tail -50 {THREAT_MONITOR_LOG}")
        return {"raw": raw.strip()}
    except Exception as e:
        logger.error(f"Failed to get anomaly summary: {e}")
        return {}


def block_ip_on_pi4(ip: str) -> tuple:
    """
    Blocks an IP locally via iptables and persists the rule.
    Returns (success: bool, message: str)
    """
    try:
        check = _run_local(f"sudo iptables -L INPUT -n | grep {ip}")
        if ip in check:
            return True, f"{ip} is already blocked."
        _run_local(f"sudo iptables -I INPUT -s {ip} -j DROP")
        _run_local("sudo netfilter-persistent save")
        return True, f"Blocked {ip} and persisted rule."
    except Exception as e:
        logger.error(f"Failed to block {ip}: {e}")
        return False, str(e)
