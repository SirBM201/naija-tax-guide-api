# app/routes/web_chat.py
from __future__ import annotations

from flask import Blueprint, request, jsonify, g

from app.routes.web_session import require_web_token
from app.core.supabase_client import supabase
from app.services.ai_service import ask_ai_chat

bp = Blueprint("web_chat", __name__)

# -----------------------------
# Sessions
# -----------------------------
@bp.get("/web/chat/sessions")
@require_web_token
def list_sessions():
    account_id = g.account_id
    r = (
        supabase()
        .table("web_chat_sessions")
        .select("id,title,created_at,updated_at")
        .eq("account_id", account_id)
        .order("updated_at", desc=True)
        .limit(50)
        .execute()
    )
    return jsonify({"ok": True, "sessions": r.data or []})


@bp.post("/web/chat/sessions")
@require_web_token
def create_session():
    account_id = g.account_id
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "Tax Assistant Chat").strip() or "Tax Assistant Chat"

    r = (
        supabase()
        .table("web_chat_sessions")
        .insert({"account_id": account_id, "title": title})
        .execute()
    )
    row = (r.data or [None])[0]
    return jsonify({"ok": True, "session": row}), 201


# -----------------------------
# Messages
# -----------------------------
@bp.get("/web/chat/sessions/<session_id>/messages")
@require_web_token
def get_messages(session_id: str):
    account_id = g.account_id

    # ensure session belongs to user
    s = (
        supabase()
        .table("web_chat_sessions")
        .select("id")
        .eq("id", session_id)
        .eq("account_id", account_id)
        .limit(1)
        .execute()
    )
    if not (s.data or []):
        return jsonify({"ok": False, "error": "session_not_found"}), 404

    r = (
        supabase()
        .table("web_chat_messages")
        .select("id,role,content,created_at")
        .eq("session_id", session_id)
        .eq("account_id", account_id)
        .order("created_at", desc=False)
        .limit(200)
        .execute()
    )
    return jsonify({"ok": True, "messages": r.data or []})


@bp.post("/web/chat/sessions/<session_id>/messages")
@require_web_token
def send_message(session_id: str):
    account_id = g.account_id
    data = request.get_json(silent=True) or {}
    user_text = (data.get("message") or "").strip()
    if not user_text:
        return jsonify({"ok": False, "error": "missing_message"}), 400

    # ensure session belongs to user
    s = (
        supabase()
        .table("web_chat_sessions")
        .select("id")
        .eq("id", session_id)
        .eq("account_id", account_id)
        .limit(1)
        .execute()
    )
    if not (s.data or []):
        return jsonify({"ok": False, "error": "session_not_found"}), 404

    # insert user message
    supabase().table("web_chat_messages").insert(
        {
            "session_id": session_id,
            "account_id": account_id,
            "role": "user",
            "content": user_text,
        }
    ).execute()

    # fetch recent history (last 30 msgs)
    h = (
        supabase()
        .table("web_chat_messages")
        .select("role,content,created_at")
        .eq("session_id", session_id)
        .eq("account_id", account_id)
        .order("created_at", desc=True)
        .limit(30)
        .execute()
    )
    history = list(reversed(h.data or []))

    # build chat messages for model
    messages = [{"role": "system", "content": "You are NaijaTax Guide. Help users with Nigerian tax questions clearly and safely."}]
    for m in history:
        r = m.get("role")
        c = m.get("content")
        if r in ("user", "assistant", "system") and c:
            messages.append({"role": r, "content": c})

    assistant_text = ask_ai_chat(messages)

    # insert assistant message
    supabase().table("web_chat_messages").insert(
        {
            "session_id": session_id,
            "account_id": account_id,
            "role": "assistant",
            "content": assistant_text,
        }
    ).execute()

    # update session updated_at
    supabase().table("web_chat_sessions").update({}).eq("id", session_id).execute()

    return jsonify({"ok": True, "assistant": assistant_text}), 200
