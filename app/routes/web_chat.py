from __future__ import annotations

from flask import Blueprint, request, jsonify, g

from app.core.auth import require_web_auth
from app.services.web_chat_service import (
    list_sessions,
    create_session,
    get_messages,
    send_message,
)

bp = Blueprint("web_chat", __name__)

@bp.route("/web/chat/sessions", methods=["GET"])
def web_chat_list_sessions():
    ok, resp = require_web_auth()
    if not ok:
        return resp
    data = list_sessions(g.account_id)
    return jsonify({"ok": True, "sessions": data}), 200

@bp.route("/web/chat/sessions", methods=["POST"])
def web_chat_create_session():
    ok, resp = require_web_auth()
    if not ok:
        return resp
    body = request.get_json(silent=True) or {}
    title = (body.get("title") or "").strip() or "New chat"
    s = create_session(g.account_id, title=title)
    return jsonify({"ok": True, "session": s}), 201

@bp.route("/web/chat/sessions/<session_id>/messages", methods=["GET"])
def web_chat_messages(session_id: str):
    ok, resp = require_web_auth()
    if not ok:
        return resp
    msgs = get_messages(g.account_id, session_id)
    return jsonify({"ok": True, "messages": msgs}), 200

@bp.route("/web/chat/sessions/<session_id>/messages", methods=["POST"])
def web_chat_send(session_id: str):
    ok, resp = require_web_auth()
    if not ok:
        return resp
    body = request.get_json(silent=True) or {}
    text = (body.get("message") or "").strip()
    if not text:
        return jsonify({"ok": False, "error": "message_required"}), 400

    out = send_message(g.account_id, session_id, text)
    return jsonify({"ok": True, **out}), 200
