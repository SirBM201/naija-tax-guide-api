from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services.ask_service import ask_guarded
from app.services.web_auth_service import get_account_id_from_request

bp = Blueprint("ask", __name__)


def _safe_json():
    return request.get_json(silent=True) or {}


@bp.post("/ask")
def ask():
    account_id = get_account_id_from_request()
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    body = _safe_json()
    question = str(body.get("question") or "").strip()
    lang = str(body.get("lang") or "en").strip().lower()
    channel = str(body.get("channel") or "web").strip().lower()

    if not question:
        return jsonify({"ok": False, "error": "missing_question", "fix": "Please enter a question."}), 400

    result = ask_guarded(
        account_id=account_id,
        question=question,
        lang=lang,
        channel=channel,
    )

    status_code = 200 if result.get("ok") else 402 if result.get("error") == "insufficient_credits" else 400
    return jsonify(result), status_code
