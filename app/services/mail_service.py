from __future__ import annotations

import os
import smtplib
import ssl
import socket
from typing import Optional, Dict, Any
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


# ---------------------------------------------------------
# ENV CONFIG (MAIL_* primary; SMTP_* fallback)
# ---------------------------------------------------------
MAIL_ENABLED = _truthy(os.getenv("MAIL_ENABLED", "0"))

MAIL_HOST = (os.getenv("MAIL_HOST") or os.getenv("SMTP_HOST") or "").strip()
MAIL_PORT = int((os.getenv("MAIL_PORT") or os.getenv("SMTP_PORT") or "587").strip() or "587")

MAIL_USER = (os.getenv("MAIL_USER") or os.getenv("SMTP_USER") or "").strip()
MAIL_PASS = (os.getenv("MAIL_PASS") or os.getenv("SMTP_PASS") or "").strip()

MAIL_FROM_NAME = (os.getenv("MAIL_FROM_NAME") or "NaijaTax Guide").strip()
MAIL_FROM_EMAIL = (os.getenv("MAIL_FROM_EMAIL") or os.getenv("SMTP_FROM") or MAIL_USER or "").strip()

MAIL_USE_SSL = _truthy(os.getenv("MAIL_USE_SSL", "0"))
MAIL_USE_TLS = _truthy(os.getenv("MAIL_USE_TLS", "1"))

DEFAULT_OTP_SUBJECT = (os.getenv("WEB_OTP_EMAIL_SUBJECT") or "Your NaijaTax Guide OTP").strip()
SMTP_TIMEOUT_SECONDS = int((os.getenv("MAIL_TIMEOUT_SECONDS") or "8").strip() or "8")


def _smtp_config_snapshot(to_email: str) -> Dict[str, Any]:
    return {
        "enabled": MAIL_ENABLED,
        "host": MAIL_HOST,
        "port": MAIL_PORT,
        "use_ssl": MAIL_USE_SSL,
        "use_tls": MAIL_USE_TLS,
        "timeout": SMTP_TIMEOUT_SECONDS,
        "user_present": bool(MAIL_USER),
        "pass_present": bool(MAIL_PASS),
        "from": f"{MAIL_FROM_NAME} <{MAIL_FROM_EMAIL}>",
        "to": to_email,
    }


def _log(stage: str, **kwargs: Any) -> None:
    try:
        print(f"[mail_service] {stage} | {kwargs}", flush=True)
    except Exception:
        pass


# ---------------------------------------------------------
# SEND EMAIL CORE
# ---------------------------------------------------------
def send_email(
    to_email: str,
    subject: str,
    html_body: str,
    text_body: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Sends transactional email via SMTP.
    Returns a structured result:
      { ok: bool, error?: str, root_cause?: str, debug?: {...} }
    """
    to_email = (to_email or "").strip().lower()
    if not to_email:
        return {"ok": False, "error": "to_email_required"}

    if not MAIL_ENABLED:
        return {
            "ok": False,
            "error": "mail_disabled",
            "debug": _smtp_config_snapshot(to_email),
        }

    if not all([MAIL_HOST, MAIL_PORT, MAIL_USER, MAIL_PASS, MAIL_FROM_EMAIL]):
        return {
            "ok": False,
            "error": "mail_not_configured",
            "debug": _smtp_config_snapshot(to_email),
        }

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{MAIL_FROM_NAME} <{MAIL_FROM_EMAIL}>"
    msg["To"] = to_email

    if text_body:
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    _log("prepare_send", to=to_email, subject=subject, config=_smtp_config_snapshot(to_email))

    try:
        if MAIL_USE_SSL:
            _log("connect_ssl_start", host=MAIL_HOST, port=MAIL_PORT, timeout=SMTP_TIMEOUT_SECONDS)
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(
                MAIL_HOST,
                MAIL_PORT,
                timeout=SMTP_TIMEOUT_SECONDS,
                context=context,
            ) as server:
                _log("connect_ssl_ok")
                server.login(MAIL_USER, MAIL_PASS)
                _log("login_ok")
                server.sendmail(MAIL_FROM_EMAIL, [to_email], msg.as_string())
                _log("sendmail_ok")
        else:
            _log("connect_start", host=MAIL_HOST, port=MAIL_PORT, timeout=SMTP_TIMEOUT_SECONDS)
            with smtplib.SMTP(MAIL_HOST, MAIL_PORT, timeout=SMTP_TIMEOUT_SECONDS) as server:
                _log("connect_ok")
                server.ehlo()
                _log("ehlo_ok")

                if MAIL_USE_TLS:
                    _log("starttls_start")
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                    _log("starttls_ok")
                    server.ehlo()
                    _log("ehlo_after_starttls_ok")

                _log("login_start", user=MAIL_USER)
                server.login(MAIL_USER, MAIL_PASS)
                _log("login_ok")

                _log("sendmail_start", from_email=MAIL_FROM_EMAIL, to=to_email)
                server.sendmail(MAIL_FROM_EMAIL, [to_email], msg.as_string())
                _log("sendmail_ok")

        return {"ok": True, "debug": _smtp_config_snapshot(to_email)}

    except smtplib.SMTPAuthenticationError as e:
        _log("smtp_auth_failed", error=repr(e))
        return {
            "ok": False,
            "error": "smtp_auth_failed",
            "root_cause": repr(e),
            "debug": _smtp_config_snapshot(to_email),
        }
    except smtplib.SMTPConnectError as e:
        _log("smtp_connect_failed", error=repr(e))
        return {
            "ok": False,
            "error": "smtp_connect_failed",
            "root_cause": repr(e),
            "debug": _smtp_config_snapshot(to_email),
        }
    except smtplib.SMTPServerDisconnected as e:
        _log("smtp_server_disconnected", error=repr(e))
        return {
            "ok": False,
            "error": "smtp_server_disconnected",
            "root_cause": repr(e),
            "debug": _smtp_config_snapshot(to_email),
        }
    except socket.timeout as e:
        _log("smtp_timeout", error=repr(e))
        return {
            "ok": False,
            "error": "smtp_timeout",
            "root_cause": repr(e),
            "debug": _smtp_config_snapshot(to_email),
        }
    except TimeoutError as e:
        _log("timeout_error", error=repr(e))
        return {
            "ok": False,
            "error": "smtp_timeout",
            "root_cause": repr(e),
            "debug": _smtp_config_snapshot(to_email),
        }
    except Exception as e:
        _log("mail_send_failed", error=repr(e))
        return {
            "ok": False,
            "error": "mail_send_failed",
            "root_cause": repr(e),
            "debug": _smtp_config_snapshot(to_email),
        }


# ---------------------------------------------------------
# OTP TEMPLATE
# ---------------------------------------------------------
def send_otp_email(to_email: str, otp_code: str) -> Dict[str, Any]:
    subject = DEFAULT_OTP_SUBJECT

    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
        <h2>NaijaTax Guide</h2>
        <p>Your One-Time Password (OTP) is:</p>

        <div style="
            font-size:32px;
            font-weight:bold;
            letter-spacing:4px;
            background:#f4f4f4;
            padding:15px;
            text-align:center;
            border-radius:8px;
        ">
            {otp_code}
        </div>

        <p>This code expires in 10 minutes.</p>
        <p>If you did not request this login, ignore this email.</p>
        <hr>
        <small>© NaijaTax Guide</small>
    </div>
    """

    text_body = f"Your OTP code is: {otp_code}\nThis code expires in 10 minutes."

    return send_email(
        to_email=to_email,
        subject=subject,
        html_body=html_body,
        text_body=text_body,
    )
