# app/services/email_service.py
from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage
from typing import Optional


def _env_first(*names: str, default: str = "") -> str:
    for n in names:
        v = os.getenv(n)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return default


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


MAIL_ENABLED = _truthy(_env_first("MAIL_ENABLED", "SMTP_ENABLED", default="0"))
MAIL_HOST = _env_first("MAIL_HOST", "SMTP_HOST")
MAIL_PORT = int((_env_first("MAIL_PORT", "SMTP_PORT", default="0") or "0").strip() or "0")
MAIL_USER = _env_first("MAIL_USER", "SMTP_USER")
MAIL_PASS = _env_first("MAIL_PASS", "SMTP_PASS")
MAIL_FROM_EMAIL = _env_first("MAIL_FROM_EMAIL", default="no-reply@thecre8hub.com")
MAIL_FROM_NAME = _env_first("MAIL_FROM_NAME", default="NaijaTax Guide")
MAIL_USE_TLS = _truthy(_env_first("MAIL_USE_TLS", default="1"))
MAIL_USE_SSL = _truthy(_env_first("MAIL_USE_SSL", default="0"))

EMAIL_DEBUG = _truthy(os.getenv("EMAIL_DEBUG", "0"))


def smtp_is_configured() -> bool:
    if not MAIL_ENABLED:
        return False
    if not MAIL_HOST or not MAIL_PORT or not MAIL_USER or not MAIL_PASS:
        return False
    return True


def smtp_debug_snapshot() -> dict:
    """
    SAFE snapshot (no secrets)
    """
    return {
        "mail_enabled": bool(MAIL_ENABLED),
        "mail_host_set": bool(MAIL_HOST),
        "mail_port": MAIL_PORT,
        "mail_user_set": bool(MAIL_USER),
        "mail_pass_set": bool(MAIL_PASS),
        "mail_use_tls": bool(MAIL_USE_TLS),
        "mail_use_ssl": bool(MAIL_USE_SSL),
        "smtp_configured": smtp_is_configured(),
    }


def send_email_otp(to_email: str, otp: str, purpose: str, ttl_minutes: int) -> Optional[str]:
    """
    Returns None if sent, else returns error string.
    """
    if not smtp_is_configured():
        return "smtp_not_configured"

    msg = EmailMessage()
    msg["From"] = f"{MAIL_FROM_NAME} <{MAIL_FROM_EMAIL}>"
    msg["To"] = to_email
    msg["Subject"] = f"Your NaijaTax Guide login code: {otp}"

    text = (
        f"Your NaijaTax Guide one-time login code is: {otp}\n\n"
        f"Purpose: {purpose}\n"
        f"This code expires in {ttl_minutes} minutes.\n\n"
        f"If you did not request this code, ignore this email."
    )
    msg.set_content(text)

    try:
        if MAIL_USE_SSL:
            with smtplib.SMTP_SSL(MAIL_HOST, MAIL_PORT, timeout=20) as server:
                server.login(MAIL_USER, MAIL_PASS)
                server.send_message(msg)
        else:
            with smtplib.SMTP(MAIL_HOST, MAIL_PORT, timeout=20) as server:
                if MAIL_USE_TLS:
                    server.starttls()
                server.login(MAIL_USER, MAIL_PASS)
                server.send_message(msg)

        return None

    except Exception as e:
        if EMAIL_DEBUG:
            return f"smtp_send_failed:{type(e).__name__}:{str(e)[:120]}"
        return f"smtp_send_failed:{type(e).__name__}"
