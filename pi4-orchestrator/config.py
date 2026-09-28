# =============================================================================
# SOC Orchestrator Configuration
# =============================================================================
import os
from dotenv import load_dotenv

load_dotenv()

# --- Pi 3 (threat-monitor) ---
PI3_HOST = "192.168.50.50"
PI3_USER = "dar"
PI3_PORT = 2222
PI3_SSH_KEY = os.environ.get("PI3_SSH_KEY", "/home/dar/.ssh/id_ed25519")
PI3_THREAT_MONITOR_DIR = "/home/dar/threat-monitor"

# --- Wazuh ---
WAZUH_HOST = "192.168.50.150"
WAZUH_PORT = 55000
WAZUH_USER = os.environ.get("WAZUH_USER", "")
WAZUH_PASS = os.environ.get("WAZUH_PASS", "")
WAZUH_ALERT_LEVEL = 12
WAZUH_INDEXER_URL = "https://127.0.0.1:19200"
WAZUH_INDEXER_USER = os.environ.get("WAZUH_INDEXER_USER", "")
WAZUH_INDEXER_PASS = os.environ.get("WAZUH_INDEXER_PASS", "")
WAZUH_AGENT_WHITELIST = ["963B", "LauMainDesk"]

# --- OpenCTI ---
OPENCTI_URL = "http://localhost:8080"
OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN", "")

# --- Telegram ---
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = int(os.environ.get("TELEGRAM_CHAT_ID", "0"))

# --- Email (daily digest) ---
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
EMAIL_RECIPIENT = os.environ.get("EMAIL_RECIPIENT", "you@example.com")
DIGEST_HOUR = 9         # 09:00 SGT
DIGEST_MINUTE = 0

# --- Thresholds ---
WAZUH_ESCALATE_LEVEL = 12
DEDUP_WINDOW_HOURS = 4          # same rule+IP won't re-alert within this window
COWRIE_PERSISTENCE_DAYS = 7     # rolling window for actor history
TELEGRAM_MIN_SEVERITY = "HIGH"  # only alert on HIGH and CRITICAL

# --- Paths ---
STATE_DB = "/home/dar/soc-orchestrator/state.db"
LOG_FILE = "/home/dar/soc-orchestrator/logs/orchestrator.log"

# --- Docker containers to monitor (on Pi 4) ---
MONITORED_CONTAINERS = [
    "opencti-opencti-1",
    "opencti-elasticsearch-1",
    "opencti-rabbitmq-1",
    "opencti-redis-1",
    "opencti-minio-1",
    "opencti-worker-1",
    "opencti-worker-2",
    "opencti-worker-3",
    "opencti-connector-mitre-1",
    "opencti-connector-alienvault-1",
    "opencti-connector-datasets-1",
    "intel-scraper",
    "grafana",
]
