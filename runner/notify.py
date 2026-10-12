"""Notifications: always stored (Admin reads them), then sent by email and/or webhook if configured."""
import smtplib
from email.message import EmailMessage

import requests

from .db import now


def _store(db, kind, assessment_id, recipient, channel, subject, body, delivery, error=None):
    db.run("INSERT INTO notifications (created_at, kind, assessment_id, recipient, channel, subject, body, delivery,"
           " error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
           (now(), kind, assessment_id, recipient, channel, subject, body, delivery, error))


def _send_email(config, to, subject, body):
    msg = EmailMessage()
    msg["From"] = config.smtp_from or config.smtp_user
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=20) as smtp:
        if config.smtp_starttls:
            smtp.starttls()
        if config.smtp_user:
            smtp.login(config.smtp_user, config.smtp_password)
        smtp.send_message(msg)


def send(db, config, kind, recipients, subject, body, assessment_id=None):
    link = f"https://{config.host}/assessments/{assessment_id}" if assessment_id else f"https://{config.host}/"
    body = f"{body}\n\n{link}\n\nCyberHealth Runner"
    for to in sorted({r for r in recipients if r}):
        if config.demo or not config.smtp_host:
            _store(db, kind, assessment_id, to, "email", subject, body,
                   "stored (demo mode)" if config.demo else "stored (no SMTP configured)")
            continue
        try:
            _send_email(config, to, subject, body)
            _store(db, kind, assessment_id, to, "email", subject, body, "sent")
        except (OSError, smtplib.SMTPException) as exc:
            _store(db, kind, assessment_id, to, "email", subject, body, "failed", str(exc))
    if config.webhook_url and not config.demo:
        try:
            resp = requests.post(config.webhook_url, json={"text": f"{subject}\n{body}"}, timeout=15)
            resp.raise_for_status()
            _store(db, kind, assessment_id, "webhook", "webhook", subject, body, "sent")
        except requests.RequestException as exc:
            _store(db, kind, assessment_id, "webhook", "webhook", subject, body, "failed", str(exc))
