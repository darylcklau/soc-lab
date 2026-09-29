import asyncio
import logging
import os
import sys
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
import pytz

import config
from alerting.telegram import build_application, send_message
from alerting.email_alert import send_daily_email
from analysis.escalation import get_escalated_alerts, build_digest
from analysis.dedup import is_duplicate_alert
from analysis import l1_triage
from connectors.wazuh import get_agent_status, get_indexer_doc_count
from connectors.docker_health import get_container_status

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

os.makedirs(os.path.dirname(config.LOG_FILE), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(config.LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("orchestrator")

# httpx/httpcore log full request URLs at INFO, which embeds the Telegram bot token.
for _noisy in ("httpx", "httpx2", "httpcore"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

SGT = pytz.timezone("Asia/Singapore")

# ---------------------------------------------------------------------------
# Filebeat divergence state (reset on orchestrator restart)
_last_indexer_count: int | None = None
# ---------------------------------------------------------------------------
# Scheduled jobs
# ---------------------------------------------------------------------------

async def job_health_check():
    """Every 15 min: check Docker + Wazuh agents; alert on anything down."""
    logger.info("Running health check")
    try:
        containers = get_container_status()
        down = [
            name for name, status in containers.items()
            if name in config.MONITORED_CONTAINERS and status != "running"
        ]
        if down:
            msg = "⚠️ <b>Container(s) DOWN:</b>\n" + "\n".join(f"  ❌ {n}: {containers[n]}" for n in down)
            await send_message(msg)
            logger.warning(f"Containers down: {down}")
    except Exception as e:
        logger.error(f"Health check (docker) failed: {e}")

    try:
        agents = get_agent_status()
        inactive = [a for a in agents if a["status"] != "active" and a["name"] not in config.WAZUH_AGENT_WHITELIST]
        if inactive:
            lines = ["⚠️ <b>Wazuh agents inactive:</b>"]
            for a in inactive:
                lines.append(f"  ❌ {a['name']} ({a['ip']}): {a['status']}")
            await send_message("\n".join(lines))
    except Exception as e:
        logger.error(f"Health check (wazuh agents) failed: {e}")
    # --- Indexer liveness check ---
    try:
        global _last_indexer_count
        current_count = get_indexer_doc_count(hours=1)
        if current_count is not None and current_count == 0 and _last_indexer_count is not None and _last_indexer_count > 0:
            msg = (
                "⚠️ <b>Wazuh indexer silent failure</b>\n"
                "Zero alerts indexed in last hour despite previous activity.\n"
                "Check: <code>systemctl status filebeat</code> on serverlaptop"
            )
            await send_message(msg)
            logger.warning("Indexer count dropped to zero — possible filebeat failure")
        _last_indexer_count = current_count
        logger.info(f"Indexer liveness: {current_count} docs indexed in last hour")
    except Exception as e:
        logger.error(f"Health check (indexer liveness) failed: {e}")


async def job_wazuh_poll():
    """Every 30 min: pull escalated alerts and send to Telegram."""
    logger.info("Running Wazuh alert poll")
    try:
        alerts = get_escalated_alerts()
        SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        min_sev = SEVERITY_ORDER.get(config.TELEGRAM_MIN_SEVERITY, 2)
        # get_escalated_alerts() can return thousands of items (e.g. a loose
        # persistent-attacker match) even though almost none of them clear the
        # Telegram severity bar. Filter FIRST, enrich only what actually escalates.
        escalated = [a for a in alerts if SEVERITY_ORDER.get(a.get("severity", ""), 0) >= min_sev]
        try:
            l1_triage.enrich_in_background(escalated)   # shadow mode: logs only, never affects sending
        except Exception as e:
            logger.error(f"L1 enrich hook failed: {e}")
        for alert in escalated:
            sev = alert.get("severity", "")
            icon = "🔴" if sev == "HIGH" else "🟡"
            msg = (
                f"{icon} <b>[{sev}] {alert['title']}</b>\n"
                f"IP: {alert.get('src_ip', 'N/A')}\n"
                f"Time: {alert.get('timestamp', '')[:19]}"
            )
            await send_message(msg)
        alerts = escalated
        if alerts:
            logger.info(f"Sent {len(alerts)} escalated alert(s)")
    except Exception as e:
        logger.error(f"Wazuh poll job failed: {e}")


async def job_l1_sweep():
    """Every 30 min: L1 triage of level 7-11 alerts (shadow mode: logs only)."""
    try:
        await l1_triage.sweep()
    except Exception as e:
        logger.error(f"L1 sweep job failed: {e}")


async def job_cowrie_persistence():
    """Every 1 hour: check for persistent Cowrie attackers (already inside get_escalated_alerts, but we run it standalone here for explicit logging)."""
    logger.info("Running Cowrie persistence check")
    # get_escalated_alerts already covers persistence; this job is a dedicated
    # hourly pass so persistence hits appear even when the 30-min poll doesn't fire.
    try:
        from analysis.persistence import check_persistent_attackers
        hits = check_persistent_attackers()
        for hit in hits:
            if is_duplicate_alert("cowrie_persistence", hit["src_ip"]):
                continue
            msg = (
                f"🔁 <b>Persistent Attacker</b>\n"
                f"IP: {hit['src_ip']}\n"
                f"Last seen: {hit['last_seen']} ({hit['gap_days']}d gap)\n"
                f"History: {', '.join(hit['past_appearances'])}"
            )
            await send_message(msg)
            logger.warning(f"Persistent attacker: {hit['src_ip']}")
    except Exception as e:
        logger.error(f"Cowrie persistence job failed: {e}")


async def job_daily_email():
    """09:00 SGT: send the rich HTML daily email."""
    logger.info("Sending daily email report")
    try:
        # Run blocking SMTP call in a thread pool so we don't block the loop
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, send_daily_email)
        await send_message("📧 Daily SOC report emailed successfully.")
    except Exception as e:
        logger.error(f"Daily email job failed: {e}")
        await send_message(f"❌ Daily email failed: {e}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    logger.info("SOC Orchestrator starting")

    # Build and start the Telegram application
    tg_app = build_application()
    await tg_app.initialize()
    await tg_app.start()
    await tg_app.updater.start_polling(drop_pending_updates=True)
    logger.info("Telegram bot polling started")

    # Build the APScheduler (AsyncIOScheduler runs on the same event loop)
    scheduler = AsyncIOScheduler(timezone=SGT)

    scheduler.add_job(
        job_health_check,
        trigger=IntervalTrigger(minutes=15, timezone=SGT),
        id="health_check",
        next_run_time=datetime.now(SGT),  # run immediately on startup
    )
    scheduler.add_job(
        job_wazuh_poll,
        trigger=IntervalTrigger(minutes=30, timezone=SGT),
        id="wazuh_poll",
    )
    scheduler.add_job(
        job_l1_sweep,
        trigger=IntervalTrigger(minutes=30, timezone=SGT),
        id="l1_sweep",
    )
    scheduler.add_job(
        job_cowrie_persistence,
        trigger=IntervalTrigger(hours=1, timezone=SGT),
        id="cowrie_persistence",
    )
#     scheduler.add_job(
#         job_daily_email,
#         trigger=CronTrigger(
#             hour=config.DIGEST_HOUR,
#             minute=config.DIGEST_MINUTE,
#             timezone=SGT,
#         ),
#         id="daily_email",
#     )

    scheduler.start()
    logger.info("Scheduler started")

    await send_message("✅ <b>SOC Orchestrator online.</b>\nCommands: /status /digest /threats /block &lt;ip&gt;")

    # Run until interrupted
    try:
        await asyncio.Event().wait()
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        logger.info("Shutting down")
        scheduler.shutdown(wait=False)
        await tg_app.updater.stop()
        await tg_app.stop()
        await tg_app.shutdown()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Stopped by user")
