# app/services/mail_service.py
from __future__ import annotations

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _int_env(name: str, default: int) -> int:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except Exception:
        return default


# ---------------------------------------------------------
# ENV CONFIG
# ---------------------------------------------------------
# NOTE:
# - Accepts MAIL_ENABLED=1/true/yes/on
# - Supports TLS/SSL toggles so SMTP never "mysteriously" fails
MAIL_ENABLED = _truthy(os.getenv("MAIL_ENABLED", ""))

MAIL_HOST = (os.getenv("MAIL_HOST") or "").strip()
MAIL_PORT = _int_env("MAIL_PORT", 2525)

MAIL_USER = (os.getenv("MAIL_USER") or "").strip()
MAIL_PASS = (os.getenv("MAIL_PASS") or "").strip()

MAIL_FROM_NAME = (os.getenv("MAIL_FROM_NAME") or "NaijaTax Guide").strip()
MAIL_FROM_EMAIL = (os.getenv("MAIL_FROM_EMAIL") or "no-reply@example.com").strip()

# Transport toggles
# - For Mailtrap sandbox: MAIL_USE_TLS=1, MAIL_USE_SSL=0, MAIL_PORT=587
MAIL_USE_TLS = _truthy(os.getenv("MAIL_USE_TLS", "1"))
MAIL_USE_SSL = _truthy(os.getenv("MAIL_USE_SSL", "0"))

# Optional diagnostics
MAIL_DEBUG = _truthy(os.getenv("MAIL_DEBUG", "0"))


# ---------------------------------------------------------
# SEND EMAIL CORE
# ---------------------------------------------------------
def send_email(
    to_email: str,
    subject: str,
    html_body: str,
    text_body: Optional[str] = None,
) -> bool:
    """
    Sends transactional email via SMTP.
    Returns True if sent successfully, otherwise False.
    """

    to_email = (to_email or "").strip()
    subject = (subject or "").strip()

    if not MAIL_ENABLED:
        print("[mail] MAIL_ENABLED is falsey -> skipping send")
        return False

    if not to_email:
        print("[mail] Missing to_email")
        return False

    if not subject:
        print("[mail] Missing subject")
        return False

    if not MAIL_HOST:
        print("[mail] Missing MAIL_HOST")
        return False

    if not MAIL_PORT:
        print("[mail] Missing MAIL_PORT")
        return False

    if not MAIL_USER or not MAIL_PASS:
        print("[mail] Missing MAIL_USER/MAIL_PASS")
        return False

    # Build email
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{MAIL_FROM_NAME} <{MAIL_FROM_EMAIL}>"
    msg["To"] = to_email

    if text_body:
        msg.attach(MIMEText(text_body, "plain", "utf-8"))

    msg.attach(MIMEText(html_body or "", "html", "utf-8"))

    # Connect and send
    try:
        if MAIL_DEBUG:
            print(
                "[mail] config:",
                {
                    "enabled": MAIL_ENABLED,
                    "host": MAIL_HOST,
                    "port": MAIL_PORT,
                    "use_tls": MAIL_USE_TLS,
                    "use_ssl": MAIL_USE_SSL,
                    "from": MAIL_FROM_EMAIL,
                    "user_present": bool(MAIL_USER),
                    "pass_present": bool(MAIL_PASS),
                },
            )

        if MAIL_USE_SSL:
            server: smtplib.SMTP = smtplib.SMTP_SSL(MAIL_HOST, MAIL_PORT, timeout=20)
        else:
            server = smtplib.SMTP(MAIL_HOST, MAIL_PORT, timeout=20)

        with server as s:
            # Some providers require EHLO before/after TLS
            s.ehlo()

            if MAIL_USE_TLS and not MAIL_USE_SSL:
                s.starttls()
                s.ehlo()

            s.login(MAIL_USER, MAIL_PASS)

            s.sendmail(
                MAIL_FROM_EMAIL,
                [to_email],
                msg.as_string(),
            )

        print(f"[mail] Sent -> {to_email}")
        return True

    except smtplib.SMTPAuthenticationError as e:
        print(f"[mail] AUTH ERROR -> {e}")
        return False
    except smtplib.SMTPException as e:
        print(f"[mail] SMTP ERROR -> {e}")
        return False
    except Exception as e:
        print(f"[mail] ERROR -> {repr(e)}")
        return False


# ---------------------------------------------------------
# OTP TEMPLATE
# ---------------------------------------------------------
def send_otp_email(to_email: str, otp_code: str) -> bool:
    """
    Sends OTP email using branded template.
    """
    otp_code = (otp_code or "").strip()
    subject = (os.getenv("WEB_OTP_EMAIL_SUBJECT") or "Your Login OTP Code").strip()

    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
        <h2 style="margin:0 0 12px 0;">NaijaTax Guide</h2>

        <p style="margin:0 0 12px 0;">Your One-Time Password (OTP) is:</p>

        <div style="
            font-size:32px;
            font-weight:bold;
            letter-spacing:4px;
            background:#f4f4f4;
            padding:15px;
            text-align:center;
            border-radius:8px;
            margin:0 0 12px 0;
        ">
            {otp_code}
        </div>

        <p style="margin:0 0 12px 0;">This code expires in 10 minutes.</p>
        <p style="margin:0 0 12px 0;">If you did not request this login, ignore this email.</p>

        <hr style="border:none;border-top:1px solid #ddd;margin:16px 0;">
        <small style="color:#666;">© NaijaTax Guide</small>
    </div>
    """.strip()

    text_body = f"Your OTP code is: {otp_code}\n\nThis code expires in 10 minutes."

    return send_email(
        to_email=to_email,
        subject=subject,
        html_body=html_body,
        text_body=text_body,
    )
