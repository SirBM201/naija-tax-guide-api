from flask import Blueprint, jsonify, request
from ..services.ask_service import ask_guarded

bp = Blueprint("ask", __name__)

@bp.post("/ask")
def ask():
    """
    Guarded by active subscription.
    Body:
      {
        "account_id": "<uuid>" OR ("provider","provider_user_id"),
        "question": "<text>",
        "lang": "en|pcm|yo|ig|ha" (optional)
      }
    """
    body = request.get_json(silent=True) or {}
    question = (body.get("question") or "").strip()
    if not question:
        return jsonify({"ok": False, "error": "question is required"}), 400

    resp = ask_guarded(body)
    return jsonify(resp)
