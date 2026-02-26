# app/core/mailer.py
from __future__ import annotations

import os
import ssl
import smtplib
from email.message import EmailMessage
from typing import Optional, Dict, Any


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def smtp_config() -> Dict[str, Any]:
    """
    Central SMTP config resolver.
    NEVER throws; always returns a dict + configured flag.
    """
    host = _env("SMTP_HOST")
    port = int(_env("SMTP_PORT", "587") or "587")
    user = _env("SMTP_USER")
    password = _env("SMTP_PASS")
    sender = _env("SMTP_FROM", user or "")
    tls = _truthy(_env("SMTP_TLS", "1"))
    ssl_enabled = _truthy(_env("SMTP_SSL", "0"))
    timeout = int(_env("SMTP_TIMEOUT", "15") or "15")

    configured = bool(host and port and sender)
    auth_configured = bool(user and password)

    return {
        "configured": configured,
        "host": host,
        "port": port,
        "user": user,
        "password_set": bool(password),
        "from": sender,
        "tls": tls,
        "ssl": ssl_enabled,
        "timeout": timeout,
        "auth_configured": auth_configured,
    }


def send_mail(
    *,
    to: str,
    subject: str,
    text: str,
    html: Optional[str] = None,
    reply_to: Optional[str] = None,
    debug: bool = False,
) -> Dict[str, Any]:
    """
    Production-safe mail sender with failure exposers.

    - NEVER crashes the app.
    - Returns {"ok": True} on success.
    - Returns {"ok": False, ...debug...} on failure with clear next steps.

    Env vars supported:
      SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
      SMTP_TLS=1/0 (default 1)
      SMTP_SSL=1/0 (default 0)
      SMTP_TIMEOUT=15
    """
    to = (to or "").strip()
    subject = (subject or "").strip()
    text = text or ""

    if not to or "@" not in to:
        return {
            "ok": False,
            "error": "invalid_recipient",
            "message": "Recipient email is missing or invalid.",
            "debug": {"to": to},
        }

    cfg = smtp_config()
    if not cfg["configured"]:
        return {
            "ok": False,
            "error": "smtp_not_configured",
            "message": "SMTP is not configured. Email sending is disabled.",
            "debug": {
                "required_env": ["SMTP_HOST", "SMTP_PORT", "SMTP_FROM"],
                "current": {k: cfg[k] for k in ["host", "port", "from", "tls", "ssl"]},
            },
        }

    msg = EmailMessage()
    msg["From"] = cfg["from"]
    msg["To"] = to
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to

    # plain
    msg.set_content(text)

    # html alternative
    if html:
        msg.add_alternative(html, subtype="html")

    host = cfg["host"]
    port = cfg["port"]
    user = cfg["user"]
    timeout = cfg["timeout"]
    tls = cfg["tls"]
    ssl_enabled = cfg["ssl"]

    try:
        if ssl_enabled:
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(host=host, port=port, timeout=timeout, context=context)
        else:
            server = smtplib.SMTP(host=host, port=port, timeout=timeout)

        with server:
            server.ehlo()
            if tls and not ssl_enabled:
                server.starttls(context=ssl.create_default_context())
                server.ehlo()

            # Only login if both user & pass exist
            if cfg["auth_configured"]:
                server.login(user, _env("SMTP_PASS"))

            server.send_message(msg)

        out = {"ok": True}
        if debug:
            out["debug"] = {
                "host": host,
                "port": port,
                "tls": tls,
                "ssl": ssl_enabled,
                "auth_used": bool(cfg["auth_configured"]),
            }
        return out

    except smtplib.SMTPAuthenticationError as e:
        return {
            "ok": False,
            "error": "smtp_auth_failed",
            "message": "SMTP authentication failed (bad SMTP_USER/SMTP_PASS).",
            "debug": {
                "exception": f"{type(e).__name__}: {str(e)[:200]}",
                "fix": "Verify SMTP_USER/SMTP_PASS. If using Gmail, use App Password and enable SMTP.",
                "config": {k: cfg[k] for k in ["host", "port", "from", "tls", "ssl", "auth_configured"]},
            },
        }
    except smtplib.SMTPConnectError as e:
        return {
            "ok": False,
            "error": "smtp_connect_failed",
            "message": "Could not connect to SMTP server.",
            "debug": {
                "exception": f"{type(e).__name__}: {str(e)[:200]}",
                "fix": "Check SMTP_HOST/SMTP_PORT and whether outbound SMTP is allowed by provider.",
                "config": {k: cfg[k] for k in ["host", "port", "tls", "ssl"]},
            },
        }
    except Exception as e:
        return {
            "ok": False,
            "error": "smtp_send_failed",
            "message": "SMTP send failed.",
            "debug": {
                "exception": f"{type(e).__name__}: {str(e)[:220]}",
                "fix": "Check SMTP env vars and provider restrictions; try SMTP_SSL=1 or SMTP_TLS=0 depending on provider.",
                "config": {k: cfg[k] for k in ["host", "port", "from", "tls", "ssl", "auth_configured"]},
            },
        }
