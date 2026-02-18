from __future__ import annotations

from flask import Blueprint, jsonify, request

from ..core.auth import require_auth_plus
from ..services.web_chat_service import (
    create_session,
    get_messages,
    get_session,
    list_sessions,
    send_user_message,
)

web_chat = Blueprint("web_chat", __name__)


@web_chat.get("/web/chat/sessions")
def list_chat_sessions():
    ctx = require_auth_plus()
    limit = int(request.args.get("limit", "50") or "50")
    limit = max(1, min(limit, 200))
    rows = list_sessions(ctx.account_id, limit=limit)
    return jsonify({"ok": True, "sessions": rows})


@web_chat.post("/web/chat/sessions")
def create_chat_session():
    ctx = require_auth_plus()
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip() or "New chat"
    row = create_session(ctx.account_id, title=title)
    return jsonify({"ok": True, "session": {"id": row.get("id"), "title": row.get("title"), "created_at": row.get("created_at")}})


@web_chat.get("/web/chat/sessions/<session_id>")
def get_chat_session(session_id: str):
    ctx = require_auth_plus()
    limit = int(request.args.get("limit", "50") or "50")
    limit = max(1, min(limit, 500))

    session = get_session(ctx.account_id, session_id)
    if not session:
        return jsonify({"ok": False, "error": "session_not_found"}), 404

    messages = get_messages(ctx.account_id, session_id, limit=limit)
    return jsonify(
        {
            "ok": True,
            "session": {"id": session.get("id"), "title": session.get("title"), "created_at": session.get("created_at"), "updated_at": session.get("updated_at")},
            "messages": messages,
        }
    )


@web_chat.post("/web/chat/sessions/<session_id>/messages")
def post_chat_message(session_id: str):
    ctx = require_auth_plus()
    data = request.get_json(silent=True) or {}
    content = (data.get("content") or "").strip()
    if not content:
        return jsonify({"ok": False, "error": "message_required"}), 400

    history_limit = int(data.get("history_limit", 12) or 12)
    history_limit = max(2, min(history_limit, 50))

    try:
        res = send_user_message(
            account_id=ctx.account_id,
            session_id=session_id,
            content=content,
            history_limit=history_limit,
        )
        return jsonify(res)
    except ValueError as e:
        msg = str(e)
        if msg == "session_not_found":
            return jsonify({"ok": False, "error": "session_not_found"}), 404
        return jsonify({"ok": False, "error": msg}), 400
    except Exception:
        return jsonify({"ok": False, "error": "chat_failed"}), 500
