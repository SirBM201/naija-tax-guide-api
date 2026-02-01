import os
import logging
from flask import Blueprint, request, jsonify

from app.core.utils import json_error
from app.core.identity import ensure_account, normalize_provider
from app.core.subscriptions import require_active_subscription
from app.services.ai_pipeline import generate_answer

log = logging.getLogger(__name__)
bp = Blueprint("ask", __name__)

ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY") or "").strip()

@bp.post("/ask")
def ask():
    body = request.get_json(silent=True) or {}

    provider = normalize_provider(body.get("provider") or "web")
    provider_user_id = (body.get("provider_user_id") or "").strip()
    question = (body.get("question") or "").strip()
    lang = (body.get("lang") or "en").strip()
    mode = (body.get("mode") or "text").strip()

    if not provider_user_id:
        return json_error("provider_user_id is required.", http_status=400)
    if not question:
        return json_error("Question is required.", http_status=400)

    # identity -> acct:<uuid>
    try:
        acct_key = ensure_account(provider, provider_user_id)
    except Exception as e:
        log.exception("identity error")
        return json_error("Identity error", http_status=400, details=str(e))

    # admin bypass
    is_admin = False
    if ADMIN_API_KEY:
        hdr = (request.headers.get("x-admin-key") or "").strip()
        if hdr and hdr == ADMIN_API_KEY:
            is_admin = True

    sub = {"status": "unknown", "plan": None, "expires_at": None, "reference": None}
    if not is_admin:
        gate = require_active_subscription(acct_key)
        sub = gate.get("sub") or sub
        if not gate.get("ok"):
            return jsonify({
                "ok": False,
                "message": gate.get("message") or "Subscription required or expired.",
                "reason": gate.get("reason") or "subscription_required",
                "subscribe_url": "/pricing",
                "plan_expiry": sub.get("expires_at"),
            }), 403

    # AI response
    answer = generate_answer(question=question, lang=lang)
    if not answer:
        # keep stable response format even if AI key missing
        answer = "AI is temporarily unavailable. Please try again shortly."

    return jsonify({
        "ok": True,
        "answer": answer,
        "audio_url": None,
        "plan_expiry": (sub.get("expires_at") if sub else None),
        "admin": is_admin,
        "acct_key": acct_key,
        "meta": {
            "provider": provider,
            "lang": lang,
            "mode": mode,
        },
    }), 200
