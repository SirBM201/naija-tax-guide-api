# app/routes/web.py
from __future__ import annotations

from typing import Any
from flask import Blueprint, jsonify, request

bp = Blueprint("web", __name__)

@bp.route("/web/ask", methods=["POST", "OPTIONS"], strict_slashes=False)
def web_ask() -> Any:
    # OPTIONS is handled by create_app preflight too, but safe to keep.
    if request.method == "OPTIONS":
        return ("", 204)

    body = request.get_json(silent=True) or {}
    q = (body.get("question") or "").strip()

    if not q:
        return jsonify({"ok": False, "error": "missing_question"}), 400

    # TODO: replace with your real service call.
    # Example:
    # from app.services.ask_service import ask_question
    # result = ask_question(q, request)
    # return jsonify(result), 200

    # Temporary safe response (so you can validate full wiring first)
    return jsonify(
        {
            "ok": True,
            "answer": "Backend route is now working. Replace this with real ask_service output.",
            "meta": {"question": q, "source": "stub"},
        }
    ), 200
