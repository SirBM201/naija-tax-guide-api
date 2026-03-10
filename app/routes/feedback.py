from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services.web_auth_service import get_account_id_from_request
from app.services.qa_feedback_service import log_feedback_and_recalculate

bp = Blueprint("feedback", __name__)


@bp.post("/feedback")
def feedback():
    account_id, debug = get_account_id_from_request(request)
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401

    body = request.get_json(silent=True) or {}

    res = log_feedback_and_recalculate(
        history_id=(body.get("history_id") or "").strip() or None,
        cache_id=(body.get("cache_id") or "").strip() or None,
        embedding_id=(body.get("embedding_id") or "").strip() or None,
        account_id=account_id,
        helpful=body.get("helpful"),
        followup_needed=bool(body.get("followup_needed", False)),
        wrong_reason=(body.get("wrong_reason") or "").strip() or None,
        user_comment=(body.get("user_comment") or "").strip() or None,
    )

    status = 200 if res.get("ok") else 400
    return jsonify(res), status
