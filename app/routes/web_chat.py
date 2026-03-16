from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from flask import Blueprint, request, jsonify

from app.core.auth import require_web_auth
from app.core.supabase_client import supabase
from app.services.ask_service import ask_guarded


bp = Blueprint("web_chat", __name__)

MAX_CONTEXT_MESSAGES = 12


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_text(v: Any, limit: int = 8000) -> str:
    s = str(v or "").strip()
    if len(s) > limit:
        s = s[:limit]
    return s


def _get_messages_for_context(session_id: str, account_id: str, limit: int) -> List[Dict[str, Any]]:
    rows = (
        supabase.table("web_chat_messages")
        .select("role,content,created_at")
        .eq("session_id", session_id)
        .eq("account_id", account_id)
        .order("created_at", desc=False)
        .limit(limit)
        .execute()
        .data
        or []
    )
    return rows


def _build_context_text(messages: List[Dict[str, Any]], new_user_text: str) -> str:
    lines: List[str] = []
    if messages:
        lines.append("Conversation so far:")
        for m in messages[-MAX_CONTEXT_MESSAGES:]:
            role = str(m.get("role") or "").strip().lower()
            content = str(m.get("content") or "").strip()
            if not content:
                continue
            if role == "assistant":
                lines.append(f"Assistant: {content}")
            elif role == "system":
                lines.append(f"System: {content}")
            else:
                lines.append(f"User: {content}")
        lines.append("")

    lines.append("New user message:")
    lines.append(new_user_text)
    lines.append("")
    lines.append("Reply as a professional Nigerian tax assistant. Be concise and practical.")
    return "\n".join(lines).strip()


@bp.get("/web/chat/sessions")
@require_web_auth
def list_sessions(ctx):
    account_id = ctx["account_id"]

    rows = (
        supabase.table("web_chat_sessions")
        .select("id,title,created_at,updated_at")
        .eq("account_id", account_id)
        .order("updated_at", desc=True)
        .limit(50)
        .execute()
        .data
        or []
    )
    return jsonify({"ok": True, "sessions": rows})


@bp.post("/web/chat/sessions")
@require_web_auth
def create_session(ctx):
    account_id = ctx["account_id"]
    body = request.get_json(silent=True) or {}
    title = _safe_text(body.get("title") or "", 120) or None

    row = {
        "account_id": account_id,
        "title": title,
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    }

    created = supabase.table("web_chat_sessions").insert(row).execute().data or []
    if not created:
        return jsonify({"ok": False, "error": "create_failed"}), 400

    return jsonify({"ok": True, "session": created[0]})


@bp.get("/web/chat/sessions/<session_id>")
@require_web_auth
def get_session(ctx, session_id: str):
    account_id = ctx["account_id"]

    s = (
        supabase.table("web_chat_sessions")
        .select("id,title,created_at,updated_at")
        .eq("id", session_id)
        .eq("account_id", account_id)
        .limit(1)
        .execute()
        .data
        or []
    )
    if not s:
        return jsonify({"ok": False, "error": "not_found"}), 404

    msgs = _get_messages_for_context(session_id, account_id, limit=50)
    return jsonify({"ok": True, "session": s[0], "messages": msgs})


@bp.get("/web/chat/sessions/<session_id>/messages")
@require_web_auth
def list_messages(ctx, session_id: str):
    account_id = ctx["account_id"]
    rows = (
        supabase.table("web_chat_messages")
        .select("id,role,content,created_at")
        .eq("session_id", session_id)
        .eq("account_id", account_id)
        .order("created_at", desc=False)
        .limit(200)
        .execute()
        .data
        or []
    )
    return jsonify({"ok": True, "messages": rows})


@bp.post("/web/chat/sessions/<session_id>/messages")
@require_web_auth
def send_message(ctx, session_id: str):
    account_id = ctx["account_id"]
    body = request.get_json(silent=True) or {}
    text = _safe_text(body.get("content") or "", 6000)
    lang = str(body.get("lang") or "en").strip() or "en"

    if not text:
        return jsonify({"ok": False, "error": "missing_content"}), 400

    s = (
        supabase.table("web_chat_sessions")
        .select("id")
        .eq("id", session_id)
        .eq("account_id", account_id)
        .limit(1)
        .execute()
        .data
        or []
    )
    if not s:
        return jsonify({"ok": False, "error": "session_not_found"}), 404

    user_row = {
        "session_id": session_id,
        "account_id": account_id,
        "role": "user",
        "content": text,
        "created_at": _now_iso(),
    }
    supabase.table("web_chat_messages").insert(user_row).execute()

    prior = _get_messages_for_context(session_id, account_id, limit=MAX_CONTEXT_MESSAGES)
    prompt = _build_context_text(prior, text)

    result = ask_guarded(
        account_id=str(account_id or "").strip(),
        question=prompt,
        lang=lang,
        channel="web_chat",
    )

    if not result.get("ok"):
        return jsonify(result), 400

    answer = str(result.get("answer") or "").strip() or "..."

    asst_row = {
        "session_id": session_id,
        "account_id": account_id,
        "role": "assistant",
        "content": answer,
        "created_at": _now_iso(),
    }
    supabase.table("web_chat_messages").insert(asst_row).execute()
    supabase.table("web_chat_sessions").update({"updated_at": _now_iso()}).eq("id", session_id).execute()

    return jsonify({"ok": True, "assistant": answer})
