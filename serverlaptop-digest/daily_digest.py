#!/usr/bin/env python3
"""Daily SOC digest email — consolidates pi4 sensor state + Wazuh fleet view."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import smtplib
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

sys.path.insert(0, str(Path(__file__).parent))
from aggregator import aggregate  # noqa: E402
from email_config import (  # noqa: E402
    APP_PASSWORD,
    RECIPIENT_EMAIL,
    SENDER_EMAIL,
    SMTP_PORT,
    SMTP_SERVER,
)

TEMPLATE_DIR = Path(__file__).parent / "templates"
SGT = timezone(timedelta(hours=8))


def is_internal(ip: str, cidrs):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if addr in ipaddress.ip_network(c):
                return True
        except ValueError:
            continue
    return False


def render(state):
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    cidrs = state.get("internal_cidrs") or []
    env.filters["is_internal"] = lambda ip: is_internal(ip, cidrs)
    env.filters["fmt_age"] = _fmt_age

    now_sgt = datetime.fromisoformat(state["generated_at_utc"]).astimezone(SGT)
    subject = f"[SOC] Daily Digest — {now_sgt.strftime('%d %b %Y')}"

    template = env.get_template("daily_digest.txt.j2")
    body = template.render(state=state, now_sgt=now_sgt)
    return subject, body


def _fmt_age(seconds):
    if seconds is None:
        return "n/a"
    s = int(seconds)
    if s < 90:
        return f"{s}s"
    if s < 5400:
        return f"{s // 60}m"
    return f"{s // 3600}h {s % 3600 // 60}m"


def send(subject, body):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECIPIENT_EMAIL
    msg.attach(MIMEText(body, "plain"))
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.ehlo()
        server.starttls()
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECIPIENT_EMAIL, msg.as_string())


def run_triage():
    """AI first-pass triage of level>=7 alerts. Advisory only; never blocks the digest.

    Runs in a subprocess with a hard timeout. Any failure becomes an
    'unavailable' entry so the digest still sends with the existing sections.
    Set ENABLE_ALERT_TRIAGE=0 in .env to turn it off.
    """
    if os.getenv("ENABLE_ALERT_TRIAGE", "1") == "0":
        return None
    try:
        p = subprocess.run([sys.executable, str(Path(__file__).parent / "triage.py")],
                           capture_output=True, text=True, timeout=720)
        if p.returncode != 0:
            tail = (p.stderr.strip().splitlines() or [f"exit {p.returncode}"])[-1]
            raise RuntimeError(tail)
        return json.loads(p.stdout)
    except Exception as e:
        return {"status": "unavailable", "error": f"{type(e).__name__}: {e}"[:200]}


TRIAGE_OK_FILE = Path(__file__).parent / "state" / "alert_triage_last_ok.txt"


def triage_health(result):
    """Health-row text for the digest. Persists the last successful run time.

    Any triage failure is RED (per the original brief, API errors are RED and the
    daily cadence means a >24h-only YELLOW state is unreachable).
    """
    if result is None:
        return None
    now = datetime.now(timezone.utc)
    if "status" not in result:
        TRIAGE_OK_FILE.parent.mkdir(exist_ok=True)
        TRIAGE_OK_FILE.write_text(now.isoformat())
        n = result["novel_count"] + result["suppressed_count"]
        return f"OK      (classified {n} alerts; last success now)"
    try:
        last = datetime.fromisoformat(TRIAGE_OK_FILE.read_text().strip())
        since = f"{(now - last).total_seconds() / 3600:.0f}h ago ({last:%Y-%m-%d %H:%MZ})"
    except (OSError, ValueError):
        since = "never recorded"
    return f"RED     (unavailable: {result['error'][:90]}; last success {since})"


def main():
    p = argparse.ArgumentParser(description="Daily SOC digest email.")
    p.add_argument("--dry-run", action="store_true",
                   help="Render body to stdout instead of sending.")
    args = p.parse_args()

    state = aggregate()
    state["alert_triage"] = run_triage()
    state["alert_triage_health"] = triage_health(state["alert_triage"])
    subject, body = render(state)

    if args.dry_run:
        print(f"Subject: {subject}\n")
        print(body)
        return

    send(subject, body)
    print(f"[{datetime.now(SGT).isoformat()}] Daily digest sent to {RECIPIENT_EMAIL}")


if __name__ == "__main__":
    main()
