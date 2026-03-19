from __future__ import annotations

import os
import uuid
from typing import Any, Dict, List, Optional, Tuple

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


def _unauthorized(auth_debug: Any):
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


def _ticket_id() -> str:
    return f"NTG-{str(uuid.uuid4()).split('-')[0].upper()}"


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
    subject = (subject or "").strip() or "Support request"
    return f"[Naija Tax Guide][{priority}][{issue_type}] {subject} | acct:{account_id}"


def _build_support_text(
    *,
    ticket_id: str,
    account_id: str,
    account: Optional[Dict[str, Any]],
    full_name: str,
    contact_email: str,
    issue_type: str,
    priority: str,
    channel: str,
    subject: str,
    message: str,
    plan_name: str = "",
    credit_balance: Any = 0,
    channel_state: str = "",
) -> str:
    account = account or {}
    lines = [
        "Naija Tax Guide Support Request",
        "",
        f"Ticket ID: {ticket_id}",
        f"Ticket Account ID: {account_id}",
        f"Display Name: {(account.get('display_name') or full_name or '').strip() or '—'}",
        f"Account Email: {(account.get('email') or '').strip() or '—'}",
        f"Submitted Contact Email: {contact_email or '—'}",
        f"Provider: {(account.get('provider') or '').strip() or '—'}",
        f"Provider User ID: {(account.get('provider_user_id') or '').strip() or '—'}",
        f"Issue Type: {issue_type or '—'}",
        f"Priority: {priority or '—'}",
        f"Channel: {channel or '—'}",
        f"Visible Plan: {plan_name or '—'}",
        f"Visible Credits: {credit_balance}",
        f"Visible Channel State: {channel_state or '—'}",
        f"Subject: {subject or '—'}",
        "",
        "Message:",
        message or "—",
    ]
    return "\n".join(lines).strip()


def _build_support_html(
    *,
    ticket_id: str,
    account_id: str,
    account: Optional[Dict[str, Any]],
    full_name: str,
    contact_email: str,
    issue_type: str,
    priority: str,
    channel: str,
    subject: str,
    message: str,
    plan_name: str = "",
    credit_balance: Any = 0,
    channel_state: str = "",
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
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    return f"""
    <div style="font-family:Arial,sans-serif;max-width:760px;margin:auto;color:#111;">
      <h2 style="margin-bottom:8px;">{cell(_support_from_name())}</h2>
      <p style="margin-top:0;color:#555;">New support request submitted from the Naija Tax Guide workspace.</p>

      <table style="border-collapse:collapse;width:100%;margin-top:16px;">
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Ticket ID</td><td style="padding:8px;border:1px solid #ddd;">{cell(ticket_id)}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Account ID</td><td style="padding:8px;border:1px solid #ddd;">{cell(account_id)}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Display Name</td><td style="padding:8px;border:1px solid #ddd;">{cell((account.get('display_name') or full_name or '').strip() or '—')}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Account Email</td><td style="padding:8px;border:1px solid #ddd;">{cell(account.get('email'))}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Submitted Contact Email</td><td style="padding:8px;border:1px solid #ddd;">{cell(contact_email)}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Provider</td><td style="padding:8px;border:1px solid #ddd;">{cell(account.get('provider'))}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Provider User ID</td><td style="padding:8px;border:1px solid #ddd;">{cell(account.get('provider_user_id'))}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Issue Type</td><td style="padding:8px;border:1px solid #ddd;">{cell(issue_type)}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Priority</td><td style="padding:8px;border:1px solid #ddd;">{cell(priority)}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Channel</td><td style="padding:8px;border:1px solid #ddd;">{cell(channel)}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Visible Plan</td><td style="padding:8px;border:1px solid #ddd;">{cell(plan_name)}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Visible Credits</td><td style="padding:8px;border:1px solid #ddd;">{cell(credit_balance)}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Visible Channel State</td><td style="padding:8px;border:1px solid #ddd;">{cell(channel_state)}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Subject</td><td style="padding:8px;border:1px solid #ddd;">{cell(subject)}</td></tr>
      </table>

      <div style="margin-top:20px;padding:16px;border:1px solid #ddd;border-radius:8px;background:#fafafa;">
        <div style="font-weight:bold;margin-bottom:8px;">Message</div>
        <div style="line-height:1.7;">{safe_message or '—'}</div>
      </div>
    </div>
    """.strip()


def _insert_ticket(record: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    try:
        res = _sb().table("support_tickets").insert(record).execute()
        rows = getattr(res, "data", None) or []
        if rows:
            return rows[0], None
        return None, {
            "error": "ticket_insert_failed",
            "root_cause": "insert returned no rows",
        }
    except Exception as e:
        return None, {
            "error": "ticket_insert_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
        }


def _insert_ticket_message(record: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    try:
        res = _sb().table("support_ticket_messages").insert(record).execute()
        rows = getattr(res, "data", None) or []
        if rows:
            return rows[0], None
        return None, {
            "error": "message_insert_failed",
            "root_cause": "insert returned no rows",
        }
    except Exception as e:
        return None, {
            "error": "message_insert_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
        }


def _latest_ticket_for_account(account_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    try:
        res = (
            _sb()
            .table("support_tickets")
            .select(
                "id,ticket_id,account_id,account_email,account_name,category,priority,subject,message,plan_name,credit_balance,channel_state,status,last_reply_at,last_reply_by,last_message_preview,created_at,updated_at"
            )
            .eq("account_id", account_id)
            .order("updated_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        if rows:
            return rows[0], None
        return None, None
    except Exception as e:
        return None, {
            "error": "latest_ticket_lookup_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
        }


def _list_tickets_for_account(account_id: str, limit: int = 20) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    try:
        safe_limit = max(1, min(int(limit or 20), 100))
        res = (
            _sb()
            .table("support_tickets")
            .select(
                "id,ticket_id,account_id,account_email,account_name,category,priority,subject,message,plan_name,credit_balance,channel_state,status,last_reply_at,last_reply_by,last_message_preview,created_at,updated_at"
            )
            .eq("account_id", account_id)
            .order("updated_at", desc=True)
            .limit(safe_limit)
            .execute()
        )
        return getattr(res, "data", None) or [], None
    except Exception as e:
        return [], {
            "error": "ticket_list_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
        }


def _find_ticket_for_account(account_id: str, ticket_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    try:
        res = (
            _sb()
            .table("support_tickets")
            .select(
                "id,ticket_id,account_id,account_email,account_name,category,priority,subject,message,plan_name,credit_balance,channel_state,status,last_reply_at,last_reply_by,last_message_preview,created_at,updated_at"
            )
            .eq("account_id", account_id)
            .eq("ticket_id", ticket_id)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        if rows:
            return rows[0], None
        return None, None
    except Exception as e:
        return None, {
            "error": "ticket_lookup_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
        }


def _list_messages_for_ticket(account_id: str, support_ticket_id: int) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    try:
        res = (
            _sb()
            .table("support_ticket_messages")
            .select("id,support_ticket_id,ticket_id,account_id,sender_type,sender_name,message,is_internal_note,created_at")
            .eq("account_id", account_id)
            .eq("support_ticket_id", support_ticket_id)
            .eq("is_internal_note", False)
            .order("created_at", desc=False)
            .execute()
        )
        return getattr(res, "data", None) or [], None
    except Exception as e:
        return [], {
            "error": "ticket_messages_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
        }


def _update_ticket_reply_state(
    *,
    ticket_pk: int,
    status: Optional[str] = None,
    last_reply_by: Optional[str] = None,
    last_message_preview: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    payload: Dict[str, Any] = {}
    if status:
        payload["status"] = status
    if last_reply_by:
        payload["last_reply_by"] = last_reply_by
    if last_message_preview is not None:
        payload["last_message_preview"] = (last_message_preview or "")[:200]

    if not payload:
        return None

    try:
        res = (
            _sb()
            .table("support_tickets")
            .update(payload)
            .eq("id", ticket_pk)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        return rows[0] if rows else None
    except Exception:
        return None


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


@bp.get("/support/latest")
def support_latest():
    account_id, auth_debug = get_account_id_from_request(request)
    if not account_id:
        return _unauthorized(auth_debug)

    ticket, lookup_err = _latest_ticket_for_account(account_id)
    if lookup_err:
        return _fail(
            error=lookup_err.get("error") or "latest_ticket_lookup_failed",
            root_cause=lookup_err.get("root_cause"),
            status=500,
        )

    return (
        jsonify(
            {
                "ok": True,
                "ticket": ticket,
                "debug": {"auth": auth_debug},
            }
        ),
        200,
    )


@bp.get("/support/tickets")
def support_tickets():
    account_id, auth_debug = get_account_id_from_request(request)
    if not account_id:
        return _unauthorized(auth_debug)

    raw_limit = request.args.get("limit", "20")
    try:
        limit = int(raw_limit)
    except Exception:
        limit = 20

    tickets, err = _list_tickets_for_account(account_id, limit=limit)
    if err:
        return _fail(
            error=err.get("error") or "ticket_list_failed",
            root_cause=err.get("root_cause"),
            status=500,
        )

    return (
        jsonify(
            {
                "ok": True,
                "tickets": tickets,
                "count": len(tickets),
                "debug": {"auth": auth_debug},
            }
        ),
        200,
    )


@bp.get("/support/tickets/<ticket_id>")
def support_ticket_detail(ticket_id: str):
    account_id, auth_debug = get_account_id_from_request(request)
    if not account_id:
        return _unauthorized(auth_debug)

    ticket_id = (ticket_id or "").strip()
    if not ticket_id:
        return _fail(
            error="ticket_id_required",
            message="Ticket ID is required.",
            status=400,
        )

    ticket, err = _find_ticket_for_account(account_id, ticket_id)
    if err:
        return _fail(
            error=err.get("error") or "ticket_lookup_failed",
            root_cause=err.get("root_cause"),
            status=500,
        )

    if not ticket:
        return _fail(
            error="ticket_not_found",
            message="Support ticket was not found for this account.",
            status=404,
        )

    messages, msg_err = _list_messages_for_ticket(account_id, int(ticket["id"]))
    if msg_err:
        return _fail(
            error=msg_err.get("error") or "ticket_messages_failed",
            root_cause=msg_err.get("root_cause"),
            status=500,
        )

    return (
        jsonify(
            {
                "ok": True,
                "ticket": ticket,
                "messages": messages,
                "debug": {"auth": auth_debug},
            }
        ),
        200,
    )


@bp.post("/support/tickets/<ticket_id>/reply")
def support_ticket_reply(ticket_id: str):
    account_id, auth_debug = get_account_id_from_request(request)
    if not account_id:
        return _unauthorized(auth_debug)

    ticket_id = (ticket_id or "").strip()
    if not ticket_id:
        return _fail(
            error="ticket_id_required",
            message="Ticket ID is required.",
            status=400,
        )

    body = _safe_json()
    message = (body.get("message") or "").strip()
    sender_name = (
        body.get("senderName")
        or body.get("sender_name")
        or body.get("fullName")
        or body.get("full_name")
        or ""
    ).strip()

    if not message:
        return _fail(
            error="message_required",
            message="Reply message is required.",
            status=400,
        )

    if len(message) < 2:
        return _fail(
            error="message_too_short",
            message="Reply message is too short.",
            extra={"min_length": 2},
            status=400,
        )

    ticket, err = _find_ticket_for_account(account_id, ticket_id)
    if err:
        return _fail(
            error=err.get("error") or "ticket_lookup_failed",
            root_cause=err.get("root_cause"),
            status=500,
        )

    if not ticket:
        return _fail(
            error="ticket_not_found",
            message="Support ticket was not found for this account.",
            status=404,
        )

    account, acct_err = _get_account_row(account_id)
    if acct_err:
        return _fail(
            error=acct_err.get("error") or "account_lookup_failed",
            root_cause=acct_err.get("root_cause"),
            extra={"fix": acct_err.get("fix")},
            status=400,
        )

    resolved_sender_name = (
        sender_name
        or (account.get("display_name") or "").strip()
        or (ticket.get("account_name") or "").strip()
        or "User"
    )

    msg_record = {
        "support_ticket_id": ticket["id"],
        "ticket_id": ticket["ticket_id"],
        "account_id": account_id,
        "sender_type": "user",
        "sender_name": resolved_sender_name,
        "message": message,
        "is_internal_note": False,
    }

    saved_message, msg_err = _insert_ticket_message(msg_record)
    if msg_err:
        return _fail(
            error=msg_err.get("error") or "message_insert_failed",
            message="Reply could not be stored.",
            root_cause=msg_err.get("root_cause"),
            status=500,
        )

    _update_ticket_reply_state(
        ticket_pk=int(ticket["id"]),
        status="open",
        last_reply_by="user",
        last_message_preview=message,
    )

    support_to = _support_to_email()
    mail_delivery: Dict[str, Any] = {"attempted": False, "ok": False}

    if support_to:
        contact_email = _best_contact_email(account, ticket.get("account_email") or "")
        mail_subject = f"[Naija Tax Guide][REPLY][{ticket['ticket_id']}] {ticket.get('subject') or 'Support ticket reply'}"
        mail_text = "\n".join(
            [
                "Naija Tax Guide Support Reply",
                "",
                f"Ticket ID: {ticket['ticket_id']}",
                f"Account ID: {account_id}",
                f"Sender: {resolved_sender_name}",
                f"Account Email: {contact_email or '—'}",
                "",
                "Reply Message:",
                message,
            ]
        ).strip()

        mail_html = f"""
        <div style="font-family:Arial,sans-serif;max-width:760px;margin:auto;color:#111;">
          <h2 style="margin-bottom:8px;">{_support_from_name().replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")}</h2>
          <p style="margin-top:0;color:#555;">A user replied to an existing support ticket.</p>

          <table style="border-collapse:collapse;width:100%;margin-top:16px;">
            <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Ticket ID</td><td style="padding:8px;border:1px solid #ddd;">{ticket['ticket_id']}</td></tr>
            <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Account ID</td><td style="padding:8px;border:1px solid #ddd;">{account_id}</td></tr>
            <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Sender</td><td style="padding:8px;border:1px solid #ddd;">{resolved_sender_name.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")}</td></tr>
            <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Subject</td><td style="padding:8px;border:1px solid #ddd;">{str(ticket.get('subject') or '—').replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")}</td></tr>
          </table>

          <div style="margin-top:20px;padding:16px;border:1px solid #ddd;border-radius:8px;background:#fafafa;">
            <div style="font-weight:bold;margin-bottom:8px;">Reply Message</div>
            <div style="line-height:1.7;">{message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\\n", "<br>")}</div>
          </div>
        </div>
        """.strip()

        mail_res = send_mail(
            to=support_to,
            subject=mail_subject,
            text=mail_text,
            html=mail_html,
            reply_to=contact_email or None,
            debug=True,
        )
        mail_delivery = {
            "attempted": True,
            "ok": bool(mail_res.get("ok")),
            "provider": mail_res.get("provider"),
            "mode": mail_res.get("mode"),
            "error": mail_res.get("error"),
            "message": mail_res.get("message"),
        }

    refreshed_ticket, _ = _find_ticket_for_account(account_id, ticket_id)

    return (
        jsonify(
            {
                "ok": True,
                "message": "Support reply submitted successfully.",
                "ticket": refreshed_ticket or ticket,
                "reply": saved_message,
                "delivery": mail_delivery,
                "debug": {"auth": auth_debug},
            }
        ),
        200,
    )


@bp.post("/support")
def submit_support():
    account_id, auth_debug = get_account_id_from_request(request)
    if not account_id:
        return _unauthorized(auth_debug)

    body = _safe_json()

    full_name = (body.get("fullName") or body.get("full_name") or body.get("account_name") or "").strip()
    contact_email = (body.get("contactEmail") or body.get("contact_email") or body.get("account_email") or "").strip().lower()
    issue_type = (body.get("issueType") or body.get("issue_type") or body.get("category") or "general").strip().lower()
    priority = (body.get("priority") or "normal").strip().lower()
    channel = (body.get("channel") or "web").strip().lower()
    subject = (body.get("subject") or "").strip()
    message = (body.get("message") or "").strip()
    plan_name = (body.get("planName") or body.get("plan_name") or "").strip()
    credit_balance = body.get("creditBalance") or body.get("credit_balance") or 0
    channel_state = (body.get("channelState") or body.get("channel_state") or "").strip()

    if issue_type not in {"general", "billing", "credits", "channels", "login", "technical"}:
        issue_type = "general"

    if priority not in {"normal", "high", "urgent"}:
        priority = "normal"

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

    final_ticket_id = _ticket_id()

    text_body = _build_support_text(
        ticket_id=final_ticket_id,
        account_id=account_id,
        account=account,
        full_name=full_name,
        contact_email=resolved_contact_email,
        issue_type=issue_type,
        priority=priority,
        channel=channel,
        subject=subject,
        message=message,
        plan_name=plan_name,
        credit_balance=credit_balance,
        channel_state=channel_state,
    )

    html_body = _build_support_html(
        ticket_id=final_ticket_id,
        account_id=account_id,
        account=account,
        full_name=full_name,
        contact_email=resolved_contact_email,
        issue_type=issue_type,
        priority=priority,
        channel=channel,
        subject=subject,
        message=message,
        plan_name=plan_name,
        credit_balance=credit_balance,
        channel_state=channel_state,
    )

    ticket_record = {
        "ticket_id": final_ticket_id,
        "account_id": account_id,
        "account_email": resolved_contact_email,
        "account_name": (account.get("display_name") or full_name or "").strip() or None,
        "category": issue_type,
        "priority": priority,
        "subject": subject,
        "message": message,
        "plan_name": plan_name or None,
        "credit_balance": int(credit_balance or 0),
        "channel_state": channel_state or None,
        "status": "open",
        "last_reply_by": "user",
        "last_message_preview": message[:200],
    }

    saved_ticket, insert_err = _insert_ticket(ticket_record)
    if insert_err:
        return _fail(
            error=insert_err.get("error") or "ticket_insert_failed",
            message="Support request could not be stored.",
            root_cause=insert_err.get("root_cause"),
            status=500,
        )

    message_record = {
        "support_ticket_id": saved_ticket["id"],
        "ticket_id": saved_ticket["ticket_id"],
        "account_id": account_id,
        "sender_type": "user",
        "sender_name": saved_ticket.get("account_name") or (account.get("display_name") or "").strip() or "User",
        "message": message,
        "is_internal_note": False,
    }

    saved_message, msg_err = _insert_ticket_message(message_record)
    if msg_err:
        return _fail(
            error=msg_err.get("error") or "message_insert_failed",
            message="Support request ticket was stored but thread initialization failed.",
            root_cause=msg_err.get("root_cause"),
            extra={"ticket": saved_ticket},
            status=500,
        )

    final_subject = _build_support_subject(
        issue_type=issue_type,
        priority=priority,
        subject=subject,
        account_id=account_id,
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
            message="Support request was stored but email delivery failed.",
            root_cause=mail_res.get("message") or mail_res.get("root_cause"),
            extra={
                "mail_debug": mail_res.get("debug"),
                "account_id": account_id,
                "ticket": saved_ticket,
                "thread_message": saved_message,
            },
            status=502,
        )

    refreshed_ticket, _ = _find_ticket_for_account(account_id, saved_ticket["ticket_id"])

    return (
        jsonify(
            {
                "ok": True,
                "message": "Support request submitted successfully.",
                "account_id": account_id,
                "ticket": refreshed_ticket or saved_ticket,
                "thread_message": saved_message,
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
