# app/routes/ask.py
from __future__ import annotations

import os

from flask import Blueprint, jsonify, request

from ..services.ask_service import ask_guarded

bp = Blueprint("ask", __name__)


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _get_bearer_token() -> str:
    h = (request.headers.get("Authorization") or "").strip()
    if h.lower().startswith("bearer "):
        return h[7:].strip()
    return ""


def _is_dev_bypass_request() -> bool:
    """
    Allow dev bypass ONLY when the request includes the correct token.
    This lets your frontend bypass mode work even when there is no subscription yet.
    """
    expected = (os.getenv("BYPASS_TOKEN") or os.getenv("DEV_BYPASS_TOKEN") or "").strip()
    if not expected:
        return False

    bearer = _get_bearer_token()
    x_token = (request.headers.get("X-Auth-Token") or "").strip()

    return bearer == expected or x_token == expected


@bp.post("/ask")
def ask():
    """
    Unified guarded AI endpoint.

    Body:
    {
      "account_id": "<uuid>"  OR
      "provider": "wa|tg|web",
      "provider_user_id": "<id>",
      "question": "<text>",
      "lang": "en|pcm|yo|ig|ha" (optional)
    }
    """
    body = request.get_json(silent=True) or {}

    question = (body.get("question") or "").strip()
    if not question:
        return jsonify({"ok": False, "error": "question_required"}), 400

    # ✅ Dev bypass support:
    # If correct bypass token is provided, mark payload for ask_service to skip subscription/credits.
    if _is_dev_bypass_request():
        body["__bypass"] = True

    try:
        resp = ask_guarded(body)

        # Business-rule failures still return 200 (frontend-friendly), except malformed input
        status = 200
        if not resp.get("ok") and resp.get("error") in {
            "invalid_request",
            "account_required",
            "question_required",
        }:
            status = 400

        return jsonify(resp), status

    except Exception:
        return jsonify({"ok": False, "error": "ask_failed"}), 500
