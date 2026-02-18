# app/routes/web_ask.py
from __future__ import annotations

from flask import Blueprint, jsonify, request

from ..core.auth import require_auth_plus
from ..services.ask_service import ask_guarded

bp = Blueprint("web_ask", __name__)

def _json() -> dict:
    try:
        return request.get_json(force=True) or {}
    except Exception:
        return {}

@bp.post("/web/ask")
@require_auth_plus
def web_ask():
    """
    Token-protected web ask endpoint.
    Frontend: POST /api/web/ask
    Body: { question: string }
    """
    account_id = getattr(request, "account_id", None)
    if not account_id:
        return jsonify({"ok": False, "error": "missing_account_id"}), 401

    data = _json()
    q = (data.get("question") or "").strip()
    if not q:
        return jsonify({"ok": False, "error": "missing_question"}), 400

    # Use the same core pipeline: library -> cache -> AI
    result = ask_guarded(question=q, account_id=account_id, mode="web")

    # Normalize response for frontend (stable keys)
    if not result.get("ok"):
        return jsonify(
            {
                "ok": False,
                "error": result.get("error") or "ask_failed",
            }
        ), 400

    return jsonify(
        {
            "ok": True,
            "answer": result.get("answer"),
            "source": result.get("source"),      # "library" | "cache" | "ai"
            "cached": bool(result.get("cached")),# bool
            "meta": {
                # keep minimal + non-sensitive
                "mode": "web",
            },
        }
    )
