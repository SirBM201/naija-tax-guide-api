# app/routes/ask.py

from flask import Blueprint, request, jsonify
from app.services.ask_service import handle_ask

bp = Blueprint("ask", __name__, url_prefix="/api")


@bp.post("/ask")
def ask_question():
    """
    Unified Ask Endpoint for ALL chat platforms

    Supported providers:
    - web
    - whatsapp
    - telegram
    - facebook
    - instagram
    - email
    """

    body = request.get_json(silent=True) or {}

    provider = (body.get("provider") or "").strip().lower()
    provider_user_id = (body.get("provider_user_id") or "").strip()
    question = (body.get("question") or "").strip()
    lang = (body.get("lang") or "en").strip().lower()

    if not provider:
        return jsonify({"ok": False, "error": "provider is required"}), 400

    if not provider_user_id:
        return jsonify({"ok": False, "error": "provider_user_id is required"}), 400

    if not question:
        return jsonify({"ok": False, "error": "question is required"}), 400

    try:
        result = handle_ask(
            provider=provider,
            provider_user_id=provider_user_id,
            question=question,
            lang=lang,
        )
        return jsonify(result)

    except Exception as e:
        return jsonify(
            {
                "ok": False,
                "error": "System error. Try again.",
                "debug": str(e),
            }
        ), 500
