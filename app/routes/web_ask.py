from __future__ import annotations

from typing import Any, Dict

from flask import Blueprint, jsonify, request, g

from app.core.auth import require_auth_plus
from app.services.ask_service import ask_guarded

bp = Blueprint("web_ask", __name__)


@bp.post("/web/ask")
@require_auth_plus
def web_ask():
    body: Dict[str, Any] = request.get_json(silent=True) or {}

    account_id = getattr(g, "account_id", None)
    question = (
        body.get("question")
        or body.get("query")
        or body.get("text")
        or body.get("message")
        or ""
    )
    lang = str(body.get("lang") or "en").strip() or "en"

    res = ask_guarded(
        account_id=str(account_id or "").strip(),
        question=str(question or "").strip(),
        lang=lang,
        channel="web",
    )

    status = 200
    if not res.get("ok") and res.get("error") in {"invalid_request", "account_required", "question_required"}:
        status = 400

    return jsonify(res), status
