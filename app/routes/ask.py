# app/routes/ask.py
from flask import Blueprint, request, jsonify
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.services.engine import resolve_answer
from app.core.identity import resolve_acct_id
from app.db.supabase_client import supabase

bp = Blueprint("ask", __name__)
log = logging.getLogger(__name__)


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _get_subscription(acct_id: str) -> Optional[Dict[str, Any]]:
    """
    Account-based subscription lookup.
    """
    try:
        r = (
            supabase()
            .table("subscriptions")
            .select("*")
            .eq("acct_id", acct_id)
            .limit(1)
            .execute()
        )
        rows = getattr(r, "data", None) or []
        return rows[0] if rows else None
    except Exception as e:
        log.exception("subscription lookup failed: %s", e)
        return None


def _is_active(sub: Optional[Dict[str, Any]]) -> bool:
    if not sub:
        return False

    status = (sub.get("status") or "").strip().lower()
    if status != "active":
        return False

    exp = sub.get("expires_at")
    if not exp:
        return False

    try:
        exp_dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
        return exp_dt > _now_utc()
    except Exception:
        return False


# ------------------------------------------------------------
# ASK (AI) — CANONICAL ENTRYPOINT
# ------------------------------------------------------------
@bp.post("/ask")
def ask():
    """
    Request JSON (canonical):
      {
        "provider": "wa" | "tg" | "web",
        "provider_user_id": "<phone | chat_id | session_id>",
        "question": "...",
        "mode": "text" | "voice",
        "lang": "en" | "pcm" | "yo" | "ig" | "ha"
      }

    Response JSON:
      {
        "ok": true,
        "answer": "...",
        "source": "cache|library|ai|fallback"
      }
    """
    data = request.get_json(silent=True) or {}

    provider = str(data.get("provider") or "").strip()
    provider_user_id = str(data.get("provider_user_id") or "").strip()
    question = str(data.get("question") or "").strip()
    mode = str(data.get("mode") or "text").strip()
    lang = str(data.get("lang") or "en").strip()

    if not provider or not provider_user_id or not question:
        return jsonify({
            "ok": False,
            "message": "provider, provider_user_id and question are required"
        }), 400

    # Resolve or create canonical account
    acct_id = resolve_acct_id(provider, provider_user_id)

    # Optional subscription check (engine still enforces limits)
    sub = _get_subscription(acct_id)
    active = _is_active(sub)

    log.info(
        "ASK acct_id=%s provider=%s active=%s lang=%s mode=%s q=%s",
        acct_id,
        provider,
        active,
        lang,
        mode,
        question[:200],
    )

    # Call the unified engine
    res = resolve_answer(
        wa_phone=acct_id,   # IMPORTANT: engine identity = acct_id
        question=question,
        mode=mode,
        lang=lang,
        source=provider,
    )

    answer_text = (
        res.get("answer_text")
        or res.get("message")
        or "Sorry, I couldn’t answer that right now."
    )

    return jsonify(
        {
            "ok": True,
            "answer": answer_text,
            "source": res.get("source"),
        }
    ), 200
