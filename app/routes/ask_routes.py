# app/routes/ask_routes.py
import os
import logging
from typing import Any, Dict

from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase
from app.core.subscriptions import require_active_subscription
from app.routes.paystack_routes import ensure_account  # reuse your ensure_account()

log = logging.getLogger(__name__)
bp = Blueprint("ask", __name__)

# If you already have OpenAI code elsewhere, call it from there.
# Here we keep it simple and safe.
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()


def json_err(message: str, status: int = 400, **extra):
    payload = {"ok": False, "message": message}
    payload.update(extra)
    return jsonify(payload), status


@bp.post("/ask")
def ask():
    """
    Body:
    {
      "provider": "web"|"wa"|"tg",
      "provider_user_id": "2348..." or telegram chat id,
      "question": "..."
    }
    """
    body = request.get_json(silent=True) or {}
    provider = (body.get("provider") or "").strip()
    provider_user_id = (body.get("provider_user_id") or "").strip()
    question = (body.get("question") or "").strip()

    if provider not in ("web", "wa", "tg"):
        return json_err("provider must be web|wa|tg", 400)
    if not provider_user_id:
        return json_err("provider_user_id is required", 400)
    if not question or len(question) < 2:
        return json_err("question is required", 400)

    # 1) Resolve identity -> acct_key
    try:
        acct_key = ensure_account(provider, provider_user_id)
    except Exception as e:
        log.exception("ensure_account failed")
        return json_err("Unable to resolve account identity", 500, detail=str(e))

    # 2) Subscription Guard
    guard = require_active_subscription(acct_key)
    if not guard["ok"]:
        return jsonify({
            "ok": False,
            "reason": guard["reason"],
            "message": guard["message"],
            "plan": guard["sub"].get("plan"),
            "expires_at": guard["sub"].get("expires_at"),
        }), 402

    # 3) Call OpenAI (placeholder)
    # IMPORTANT: keep your real OpenAI implementation here.
    if not OPENAI_API_KEY:
        # Don’t crash the app in production if missing
        return json_err("OPENAI_API_KEY not configured", 500)

    try:
        # Replace this with your real OpenAI call
        answer = f"(demo) Answer: {question}"

        # 4) Optional: log usage (recommended)
        # Create a small table like ai_usage_log or reuse your existing usage tables.
        try:
            supabase().table("ai_usage_log").insert({
                "acct_key": acct_key,
                "provider": provider,
                "provider_user_id": provider_user_id,
                "question": question[:800],
                "answer": answer[:1200],
            }).execute()
        except Exception:
            pass

        return jsonify({
            "ok": True,
            "acct_key": acct_key,   # safe debug
            "answer": answer,
            "plan": guard["sub"].get("plan"),
            "expires_at": guard["sub"].get("expires_at"),
        }), 200

    except Exception as e:
        log.exception("ask failed")
        return json_err("AI request failed", 500, detail=str(e))
