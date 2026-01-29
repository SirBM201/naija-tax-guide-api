# app/routes/ask.py
from flask import Blueprint, request, jsonify
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.services.engine import resolve_answer
from app.core.identity import resolve_acct_id, acct_key, get_subscription_by_acct_key

bp = Blueprint("ask", __name__)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _is_active(sub: Optional[Dict[str, Any]]) -> bool:
    if not sub:
        return False

    status = (sub.get("status") or "").strip().lower()
    if status and status not in ("active", "paid"):
        return False

    exp = sub.get("expires_at")
    if not exp:
        return False

    try:
        exp_dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
        return exp_dt > _now_utc()
    except Exception:
        return False


@bp.post("/ask")
def ask():
    """
    Preferred Request JSON (NEW):
      {
        "provider": "wa" | "tg" | "web",
        "provider_user_id": "<wa_id | tg_user_id | web_session_id>",
        "question": "...",
        "mode": "text" | "voice",
        "lang": "en" | "pcm" | "yo" | "ig" | "ha"
      }

    Backward-compatible (OLD):
      {
        "wa_phone": "2348012345678",
        "question": "..."
      }
    """
    data = request.get_json(silent=True) or {}

    provider = str(data.get("provider") or "").strip().lower()
    provider_user_id = str(data.get("provider_user_id") or "").strip()

    # Backward compat: if frontend still sends wa_phone/user_key, treat it as web identity for now
    legacy_user = str(data.get("wa_phone") or data.get("user_key") or "").strip()
    if (not provider or not provider_user_id) and legacy_user:
        provider = "web"
        provider_user_id = legacy_user

    question = str(data.get("question") or "").strip()
    mode = str(data.get("mode") or "text").strip()
    lang = str(data.get("lang") or "en").strip()

    if not provider or not provider_user_id or not question:
        return jsonify({"ok": False, "message": "provider, provider_user_id, question required"}), 400

    # Resolve/create account
    try:
        acct_id = resolve_acct_id(provider, provider_user_id)
        identity = acct_key(acct_id)  # 'acct:<uuid>'
    except Exception as e:
        logging.exception("identity resolve failed: %s", e)
        return jsonify({"ok": False, "message": "identity resolution failed"}), 500

    # Subscription lookup (fast) - engine can enforce too
    sub = get_subscription_by_acct_key(identity)
    active = _is_active(sub)

    logging.info(
        "ASK provider=%s provider_user_id=%s acct=%s active=%s lang=%s mode=%s q=%s",
        provider, provider_user_id, identity, active, lang, mode, question[:200]
    )

    # IMPORTANT: keep engine arg name wa_phone, but value is now account identity
    res = resolve_answer(
        wa_phone=identity,
        question=question,
        mode=mode,
        lang=lang,
        source=provider,   # 'wa' | 'tg' | 'web'
    )

    # If engine returns blocked/denied, pass it through cleanly
    if not res or res.get("ok") is False:
        return jsonify({
            "ok": False,
            "message": res.get("message") or res.get("reason") or "blocked",
            "reason": res.get("reason"),
            "subscribe_url": res.get("subscribe_url"),
            "plan_expiry": res.get("plan_expiry"),
        }), 200

    return jsonify(
        {
            "ok": True,
            "answer": res.get("answer_text"),
            "audio_url": res.get("audio_url"),
            "plan_expiry": res.get("plan_expiry"),
            "source": res.get("source"),
            "identity": identity,
        }
    ), 200
