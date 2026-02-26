# app/core/mailer.py
from __future__ import annotations

import os
from typing import Optional, Dict, Any


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _mail_config_snapshot() -> Dict[str, Any]:
    """
    Returns a safe snapshot of mail configuration (no secrets).
    Supports both MAIL_* and SMTP_* conventions.
    """
    # Preferred in your repo:
    mail_enabled = _truthy(_env("MAIL_ENABLED", "false"))
    mail_host = _env("MAIL_HOST", "")
    mail_port = int(_env("MAIL_PORT", "2525") or "2525")
    mail_user = _env("MAIL_USER", "")
    mail_from_email = _env("MAIL_FROM_EMAIL", "")
    mail_from_name = _env("MAIL_FROM_NAME", "NaijaTax Guide")
    mail_pass_set = bool(_env("MAIL_PASS", ""))

    # Optional SMTP_* compatibility:
    smtp_host = _env("SMTP_HOST", "")
    smtp_port = int(_env("SMTP_PORT", "587") or "587")
    smtp_user = _env("SMTP_USER", "")
    smtp_from = _env("SMTP_FROM", "")
    smtp_pass_set = bool(_env("SMTP_PASS", ""))

    return {
        "MAIL_ENABLED": mail_enabled,
        "MAIL_HOST": mail_host,
        "MAIL_PORT": mail_port,
        "MAIL_USER_set": bool(mail_user),
        "MAIL_PASS_set": mail_pass_set,
        "MAIL_FROM_EMAIL": mail_from_email,
        "MAIL_FROM_NAME": mail_from_name,
        "SMTP_HOST": smtp_host,
        "SMTP_PORT": smtp_port,
        "SMTP_USER_set": bool(smtp_user),
        "SMTP_PASS_set": smtp_pass_set,
        "SMTP_FROM": smtp_from,
    }


def _detect_mode() -> str:
    """
    Decide which mail stack to use.
    Priority:
      1) app.services.mail_service (your repo)
      2) SMTP_* direct (if you later add a direct SMTP sender)
    """
    try:
        from app.services import mail_service as _ms  # noqa: F401
        return "repo_mail_service"
    except Exception:
        # no mail_service (unlikely in your repo, but safe)
        return "none"


def send_mail(
    *,
    to: str,
    subject: str,
    text: str,
    html: Optional[str] = None,
    reply_to: Optional[str] = None,
    debug: bool = True,
) -> Dict[str, Any]:
    """
    Unified mail sender with failure exposers.

    Returns:
      {"ok": True, ...}
      {"ok": False, "error": "...", "message": "...", "debug": {...}}

    IMPORTANT:
    - NEVER raises (so it can’t crash your Gunicorn boot or request flow).
    """
    to = (to or "").strip()
    subject = (subject or "").strip()
    text = text or ""
    html = html or ""

    if not to or "@" not in to:
        return {
            "ok": False,
            "error": "invalid_recipient",
            "message": "Recipient email is missing or invalid.",
            "debug": {"to": to},
        }

    mode = _detect_mode()
    cfg = _mail_config_snapshot()

    # ---------- MODE: repo mail_service ----------
    if mode == "repo_mail_service":
        try:
            from app.services.mail_service import send_email

            # app/services/mail_service.py expects HTML body; it can also accept text_body.
            ok = send_email(
                to_email=to,
                subject=subject,
                html_body=html or f"<pre>{text}</pre>",
                text_body=text or None,
            )

            if ok:
                return {
                    "ok": True,
                    "provider": "smtp",
                    "mode": "repo_mail_service",
                    "to": to,
                    "subject": subject,
                }

            # If send_email returns False, expose why (best-effort)
            # In your mail_service it returns False if disabled OR missing config OR exception.
            # We expose the most likely reason based on env snapshot.
            if not cfg["MAIL_ENABLED"]:
                reason = "MAIL_ENABLED=false"
                fix = "Set MAIL_ENABLED=true in Koyeb env vars to enable email sending."
            elif not (cfg["MAIL_HOST"] and cfg["MAIL_PORT"] and cfg["MAIL_USER_set"] and cfg["MAIL_PASS_set"]):
                reason = "missing_MAIL_smtp_config"
                fix = "Set MAIL_HOST, MAIL_PORT, MAIL_USER, MAIL_PASS, MAIL_FROM_EMAIL in Koyeb env vars."
            else:
                reason = "smtp_send_failed_or_blocked"
                fix = "Check SMTP credentials, TLS requirements, and whether provider blocks outbound SMTP."

            return {
                "ok": False,
                "error": "mail_send_failed",
                "message": "Email send failed (see debug for likely cause).",
                "debug": {
                    "mode": mode,
                    "likely_reason": reason,
                    "recommended_fix": fix,
                    "config_snapshot": cfg if debug else {},
                },
            }

        except Exception as e:
            return {
                "ok": False,
                "error": "mailer_exception",
                "message": "Mailer threw an exception (caught safely).",
                "debug": {
                    "mode": mode,
                    "exception": f"{type(e).__name__}: {str(e)[:220]}",
                    "config_snapshot": cfg if debug else {},
                    "fix": "Ensure app/services/mail_service.py exists and is importable, and required env vars are set.",
                },
            }

    # ---------- MODE: none ----------
    return {
        "ok": False,
        "error": "mailer_not_available",
        "message": "No mail backend is available in this build.",
        "debug": {
            "mode": mode,
            "config_snapshot": cfg if debug else {},
            "fix": "Ensure app/services/mail_service.py exists OR add SMTP sender implementation.",
        },
    }


def send_otp_email(*, to: str, otp_code: str) -> Dict[str, Any]:
    """
    OTP email wrapper with failure exposers.
    Uses app/services/mail_service.send_otp_email if available,
    otherwise falls back to send_mail with a basic template.
    """
    to = (to or "").strip()
    otp_code = (otp_code or "").strip()

    if not to or "@" not in to:
        return {"ok": False, "error": "invalid_recipient", "message": "Invalid email address.", "debug": {"to": to}}

    if not otp_code or len(otp_code) < 4:
        return {"ok": False, "error": "invalid_otp", "message": "OTP code is missing/invalid.", "debug": {"otp_len": len(otp_code)}}

    try:
        from app.services.mail_service import send_otp_email as _send_otp_email

        ok = _send_otp_email(to_email=to, otp_code=otp_code)
        if ok:
            return {"ok": True, "mode": "repo_mail_service", "to": to}

        # best-effort failure exposer
        cfg = _mail_config_snapshot()
        return {
            "ok": False,
            "error": "otp_mail_send_failed",
            "message": "OTP email send failed (repo mail_service returned False).",
            "debug": {
                "likely_reason": "MAIL_ENABLED=false OR missing MAIL_* config OR SMTP blocked",
                "config_snapshot": cfg,
                "fix": "Set MAIL_ENABLED=true and configure MAIL_HOST/MAIL_PORT/MAIL_USER/MAIL_PASS/MAIL_FROM_EMAIL on Koyeb.",
            },
        }

    except Exception:
        # fallback template if mail_service import breaks
        subject = "Your Login OTP Code"
        text = f"Your OTP code is: {otp_code}\n\nThis code expires in 10 minutes."
        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
          <h2>NaijaTax Guide</h2>
          <p>Your One-Time Password (OTP) is:</p>
          <div style="font-size:32px;font-weight:bold;letter-spacing:4px;background:#f4f4f4;padding:15px;text-align:center;border-radius:8px">
            {otp_code}
          </div>
          <p>This code expires in 10 minutes.</p>
          <p>If you did not request this login, ignore this email.</p>
          <hr><small>© NaijaTax Guide</small>
        </div>
        """
        return send_mail(to=to, subject=subject, text=text, html=html)
