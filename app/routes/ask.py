from flask import Blueprint, request, jsonify
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from app.core.identity import resolve_acct_id
from app.services.engine import resolve_answer
from app.db.supabase_client import supabase

bp = Blueprint("ask", __name__)
log = logging.getLogger(__name__)


def _now_utc():
    return datetime.now(timezone.utc)


def _get_subscription(acct_id: str) -> Optional[Dict[str, Any]]:
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


def _is_active(sub: Optional[Dict[str, Any]]) -> bool:
    if not sub or sub.get("status") != "active":
        return False
    exp = sub.get("expires_at")
    return exp and datetime.fromisoformat(exp.replace("Z", "+00:00")) > _now_utc()


@bp.post("/ask")
def ask():
    data = request.get_json(silent=True) or {}

    provider = str(data.get("provider") or "").strip()
    provider_user_id = str(data.get("provider_user_id") or "").strip()
    question = str(data.get("question") or "").strip()
    lang = str(data.get("lang") or "en").strip()
    mode = str(data.get("mode") or "text").strip()

    if not provider or not provider_user_id or not question:
        return jsonify({"ok": False, "message": "provider, provider_user_id and question required"}), 400

    acct_id = resolve_acct_id(provider, provider_user_id)
    sub = _get_subscription(acct_id)
    active = _is_active(sub)

    log.info("ASK acct=%s provider=%s active=%s q=%s", acct_id, provider, active, question[:120])

    res = resolve_answer(
        wa_phone=acct_id,   # legacy param = identity
        question=question,
        mode=mode,
        lang=lang,
        source=provider,
    )

    return jsonify({
        "ok": True,
        "answer": res.get("answer_text") or res.get("message"),
        "source": res.get("source"),
    })
