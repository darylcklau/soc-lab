import logging
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
import config

logger = logging.getLogger(__name__)

# =============================================================================
# Send a message to your Telegram chat
# =============================================================================

async def send_message(text: str):
    """Send a plain text message to the configured chat."""
    app = Application.builder().token(config.TELEGRAM_TOKEN).build()
    async with app:
        await app.bot.send_message(
            chat_id=config.TELEGRAM_CHAT_ID,
            text=text,
            parse_mode="HTML"
        )

# =============================================================================
# Command handlers
# =============================================================================

async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Return current health of all services."""
    from connectors.docker_health import get_container_status
    from connectors.wazuh import get_agent_status

    lines = ["🖥️ <b>Service Status</b>"]

    # Docker containers
    lines.append("\n<b>Docker (Pi 4):</b>")
    containers = get_container_status()
    for name, status in containers.items():
        icon = "✅" if status == "running" else "❌"
        lines.append(f"  {icon} {name}: {status}")

    # Wazuh agents
    lines.append("\n<b>Wazuh Agents:</b>")
    agents = get_agent_status()
    for agent in agents:
        icon = "✅" if agent["status"] == "active" else "❌"
        lines.append(f"  {icon} {agent['name']}: {agent['status']}")

    await update.message.reply_text("\n".join(lines), parse_mode="HTML")


async def cmd_digest(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Trigger an on-demand 24h summary."""
    await update.message.reply_text("⏳ Generating digest, please wait...")
    from analysis.escalation import build_digest
    digest = build_digest()
    await update.message.reply_text(digest, parse_mode="HTML")


async def cmd_block(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Remotely block an IP on Pi 3."""
    if not context.args:
        await update.message.reply_text("Usage: /block <ip>")
        return

    ip = context.args[0]

    # Basic IP format sanity check
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        await update.message.reply_text(f"❌ Invalid IP format: {ip}")
        return

    await update.message.reply_text(f"⏳ Blocking {ip} on Pi 4...")

    from connectors.threat_monitor import block_ip_on_pi4
    success, message = block_ip_on_pi4(ip)

    if success:
        await update.message.reply_text(f"✅ {ip} blocked on Pi 4.\n{message}")
    else:
        await update.message.reply_text(f"❌ Failed to block {ip}.\n{message}")


async def cmd_threats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Last 24h threat summary."""
    from connectors.wazuh import get_recent_alerts
    from connectors.cowrie import get_recent_sessions

    lines = ["🛡️ <b>24h Threat Summary</b>"]

    # Wazuh alerts
    alerts = get_recent_alerts(hours=24, min_level=10)
    lines.append(f"\n<b>Wazuh Alerts (level 10+):</b> {len(alerts)}")
    for a in alerts[:5]:  # top 5
        lines.append(f"  • [{a['level']}] {a['description']} — {a.get('src_ip', 'N/A')}")
    if len(alerts) > 5:
        lines.append(f"  ... and {len(alerts) - 5} more")

    # Cowrie sessions
    sessions = get_recent_sessions(hours=24)
    lines.append(f"\n<b>Cowrie Sessions:</b> {len(sessions)}")
    unique_ips = len(set(s["src_ip"] for s in sessions))
    lines.append(f"  Unique source IPs: {unique_ips}")

    await update.message.reply_text("\n".join(lines), parse_mode="HTML")


# =============================================================================
# Bot runner — called from orchestrator.py
# =============================================================================

def build_application():
    """Build and return the configured Telegram application."""
    app = Application.builder().token(config.TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("digest", cmd_digest))
    app.add_handler(CommandHandler("block", cmd_block))
    app.add_handler(CommandHandler("threats", cmd_threats))
    return app

