# app/routes/web_ask.py
from __future__ import annotations

from flask import Blueprint, request, jsonify, g

from app.routes.web_session import require_web_token
from app.services.ask_service import handle_ask

bp = Blueprint("web_ask", __name__)

@bp.post("/web/ask")
@require_web_token
def web_ask():
    data = request.get_json(silent=True) or {}
    q = (data.get("question") or "").strip()

    if not q:
        return jsonify({"ok": False, "error": "missing_question"}), 400

    account_id = getattr(g, "account_id", None)
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    res = handle_ask(
        question=q,
        account_id=account_id,
        provider="web",
        provider_user_id=str(account_id),
        meta={"channel": "web", "mode": "ask"},
    )

    res["ok"] = True
    return jsonify(res), 200
