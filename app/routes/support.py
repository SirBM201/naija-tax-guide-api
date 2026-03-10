from __future__ import annotations

import os
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, jsonify, request

from app.core.mailer import send_mail
from app.core.supabase_client import supabase
from app.services.web_auth_service import get_account_id_from_request

bp = Blueprint("support", __name__)


def _sb():
    return supabase() if callable(supabase) else supabase


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


def _clip(v: Any, n: int = 400) -> str:
    s = str(v or "")
    return s if len(s) <= n else s[:n] + "...<truncated>"


def _safe_json() -> Dict[str, Any]:
    return request.get_json(silent=True) or {}


def _fail(
    *,
    error: str,
    message: Optional[str] = None,
    root_cause: Any = None,
    extra: Optional[Dict[str, Any]] = None,
    status: int = 400,
):
    out: Dict[str, Any] = {"ok": False, "error": error}
    if message:
        out["message"] = message
    if root_cause is not None:
        out["root_cause"] = root_cause
    if extra:
        out.update(extra)
    return jsonify(out), status


def _get_account_row(account_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    account_id = (account_id or "").strip()
    if not account_id:
        return None, {
            "error": "account_id_required",
            "root_cause": "missing_account_id",
            "fix": "Authenticate first so canonical accounts.account_id can be resolved.",
        }

    try:
        q = (
            _sb()
            .table("accounts")
            .select(
                "id,account_id,email,provider,provider_user_id,display_name,phone,phone_e164,created_at,updated_at"
            )
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = getattr(q, "data", None) or []
        if rows:
            return rows[0], None
    except Exception as e:
        return None, {
            "error": "account_lookup_failed",
            "root_cause": f"lookup by account_id failed: {type(e).__name__}: {_clip(e)}",
        }

    try:
        q = (
            _sb()
            .table("accounts")
            .select(
                "id,account_id,email,provider,provider_user_id,display_name,phone,phone_e164,created_at,updated_at"
            )
            .eq("id", account_id)
            .limit(1)
            .execute()
        )
        rows = getattr(q, "data", None) or []
        if rows:
            return rows[0], None
    except Exception as e:
        return None, {
            "error": "account_lookup_failed",
            "root_cause": f"lookup by id failed: {type(e).__name__}: {_clip(e)}",
        }

    return None, {
        "error": "account_not_found",
        "root_cause": "no accounts row matched provided account_id",
    }


def _best_contact_email(account: Optional[Dict[str, Any]], submitted_email: str) -> str:
    submitted_email = (submitted_email or "").strip().lower()
    if "@" in submitted_email:
        return submitted_email

    account = account or {}
    email = (account.get("email") or "").strip().lower()
    if "@" in email:
        return email

    provider = (account.get("provider") or "").strip().lower()
    provider_user_id = (account.get("provider_user_id") or "").strip().lower()
    if provider == "web" and "@" in provider_user_id:
        return provider_user_id

    return ""


def _support_to_email() -> str:
    return (
        _env("SUPPORT_TO_EMAIL")
        or _env("SUPPORT_EMAIL")
        or _env("MAIL_FROM_EMAIL")
        or _env("SMTP_FROM")
        or _env("MAIL_USER")
        or _env("SMTP_USER")
    )


def _support_from_name() -> str:
    return _env("SUPPORT_FROM_NAME", "Naija Tax Guide Support")


def _build_support_subject(issue_type: str, priority: str, subject: str, account_id: str) -> str:
    issue_type = (issue_type or "general").strip()
    priority = (priority or "normal").strip().upper()
    subject = (subject or "").strip()
    if not subject:
        subject = "Support request"
    return f"[Naija Tax Guide][{priority}][{issue_type}] {subject} | acct:{account_id}"


def _build_support_text(
    *,
    account_id: str,
    account: Optional[Dict[str, Any]],
    full_name: str,
    contact_email: str,
    issue_type: str,
    priority: str,
    channel: str,
    subject: str,
    message: str,
) -> str:
    account = account or {}
    lines = [
        "Naija Tax Guide Support Request",
        "",
        f"Account ID: {account_id}",
        f"Display Name: {(account.get('display_name') or full_name or '').strip() or '—'}",
        f"Account Email: {(account.get('email') or '').strip() or '—'}",
        f"Submitted Contact Email: {contact_email or '—'}",
        f"Provider: {(account.get('provider') or '').strip() or '—'}",
        f"Provider User ID: {(account.get('provider_user_id') or '').strip() or '—'}",
        f"Issue Type: {issue_type or '—'}",
        f"Priority: {priority or '—'}",
        f"Channel: {channel or '—'}",
        f"Subject: {subject or '—'}",
        "",
        "Message:",
        message or "—",
    ]
    return "\n".join(lines).strip()


def _build_support_html(
    *,
    account_id: str,
    account: Optional[Dict[str, Any]],
    full_name: str,
    contact_email: str,
    issue_type: str,
    priority: str,
    channel: str,
    subject: str,
    message: str,
) -> str:
    account = account or {}
    safe_message = (
        (message or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br>")
    )

    def cell(v: Any) -> str:
        s = str(v or "—")
        return (
            s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    return f"""
    <div style="font-family:Arial,sans-serif;max-width:760px;margin:auto;color:#111;">
      <h2 style="margin-bottom:8px;">{cell(_support_from_name())}</h2>
      <p style="margin-top:0;color:#555;">New support request submitted from the Naija Tax Guide workspace.</p>

      <table style="border-collapse:collapse;width:100%;margin-top:16px;">
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Account ID</td><td style="padding:8px;border:1px solid #ddd;">{cell(account_id)}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Display Name</td><td style="padding:8px;border:1px solid #ddd;">{cell((account.get('display_name') or full_name or '').strip() or '—')}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Account Email</td><td style="padding:8px;border:1px solid #ddd;">{cell(account.get('email'))}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Submitted Contact Email</td><td style="padding:8px;border:1px solid #ddd;">{cell(contact_email)}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Provider</td><td style="padding:8px;border:1px solid #ddd;">{cell(account.get('provider'))}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Provider User ID</td><td style="padding:8px;border:1px solid #ddd;">{cell(account.get('provider_user_id'))}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Issue Type</td><td style="padding:8px;border:1px solid #ddd;">{cell(issue_type)}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Priority</td><td style="padding:8px;border:1px solid #ddd;">{cell(priority)}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Channel</td><td style="padding:8px;border:1px solid #ddd;">{cell(channel)}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Subject</td><td style="padding:8px;border:1px solid #ddd;">{cell(subject)}</td></tr>
      </table>

      <div style="margin-top:20px;padding:16px;border:1px solid #ddd;border-radius:8px;background:#fafafa;">
        <div style="font-weight:bold;margin-bottom:8px;">Message</div>
        <div style="line-height:1.7;">{safe_message or '—'}</div>
      </div>
    </div>
    """.strip()


@bp.get("/support/health")
def support_health():
    to_email = _support_to_email()
    return (
        jsonify(
            {
                "ok": True,
                "route_group": "support",
                "mail_ready": bool(to_email),
                "support_to_email": to_email or None,
            }
        ),
        200,
    )


@bp.post("/support")
def submit_support():
    account_id, auth_debug = get_account_id_from_request(request)
    if not account_id:
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "unauthorized",
                    "debug": auth_debug,
                }
            ),
            401,
        )

    body = _safe_json()

    full_name = (body.get("fullName") or body.get("full_name") or "").strip()
    contact_email = (body.get("contactEmail") or body.get("contact_email") or "").strip().lower()
    issue_type = (body.get("issueType") or body.get("issue_type") or "general").strip().lower()
    priority = (body.get("priority") or "normal").strip().lower()
    channel = (body.get("channel") or "web").strip().lower()
    subject = (body.get("subject") or "").strip()
    message = (body.get("message") or "").strip()

    if not subject:
        return _fail(
            error="subject_required",
            message="Support subject is required.",
            status=400,
        )

    if not message:
        return _fail(
            error="message_required",
            message="Support message is required.",
            status=400,
        )

    if len(message) < 10:
        return _fail(
            error="message_too_short",
            message="Support message is too short.",
            extra={"min_length": 10},
            status=400,
        )

    account, acct_err = _get_account_row(account_id)
    if acct_err:
        return _fail(
            error=acct_err.get("error") or "account_lookup_failed",
            root_cause=acct_err.get("root_cause"),
            extra={"fix": acct_err.get("fix")},
            status=400,
        )

    resolved_contact_email = _best_contact_email(account, contact_email)
    if not resolved_contact_email:
        return _fail(
            error="contact_email_required",
            message="A valid support contact email is required.",
            root_cause="No valid submitted or account-linked email address was found.",
            extra={
                "fix": "Submit contactEmail from the frontend or ensure accounts.email is populated.",
                "account_id": account_id,
            },
            status=400,
        )

    support_to = _support_to_email()
    if not support_to:
        return _fail(
            error="support_email_not_configured",
            message="Support inbox is not configured on the backend.",
            root_cause="SUPPORT_TO_EMAIL / SUPPORT_EMAIL / MAIL_FROM_EMAIL is missing.",
            extra={
                "fix": "Set SUPPORT_TO_EMAIL in backend environment variables.",
            },
            status=500,
        )

    final_subject = _build_support_subject(
        issue_type=issue_type,
        priority=priority,
        subject=subject,
        account_id=account_id,
    )

    text_body = _build_support_text(
        account_id=account_id,
        account=account,
        full_name=full_name,
        contact_email=resolved_contact_email,
        issue_type=issue_type,
        priority=priority,
        channel=channel,
        subject=subject,
        message=message,
    )

    html_body = _build_support_html(
        account_id=account_id,
        account=account,
        full_name=full_name,
        contact_email=resolved_contact_email,
        issue_type=issue_type,
        priority=priority,
        channel=channel,
        subject=subject,
        message=message,
    )

    mail_res = send_mail(
        to=support_to,
        subject=final_subject,
        text=text_body,
        html=html_body,
        reply_to=resolved_contact_email,
        debug=True,
    )

    if not mail_res.get("ok"):
        return _fail(
            error=mail_res.get("error") or "support_send_failed",
            message="Support request could not be delivered.",
            root_cause=mail_res.get("message") or mail_res.get("root_cause"),
            extra={
                "mail_debug": mail_res.get("debug"),
                "account_id": account_id,
            },
            status=502,
        )

    return (
        jsonify(
            {
                "ok": True,
                "message": "Support request submitted successfully.",
                "account_id": account_id,
                "delivery": {
                    "to": support_to,
                    "reply_to": resolved_contact_email,
                    "provider": mail_res.get("provider"),
                    "mode": mail_res.get("mode"),
                },
                "debug": {
                    "auth": auth_debug,
                },
            }
        ),
        200,
    )
