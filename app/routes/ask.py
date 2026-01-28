from flask import Blueprint, request, jsonify
import logging

from app.core.identity import resolve_acct_id
from app.core.rate_limit import increment_and_check
from app.services.engine import resolve_answer
from app.core.subscriptions import is_paid_active

bp = Blueprint("ask", __name__)
log = logging.getLogger(__name__)

@bp.post("/ask")
def ask():
    d = request.get_json(silent=True) or {}

    provider = (d.get("provider") or "").strip()          # "web" | "tg" | "wa"
    provider_user_id = (d.get("provider_user_id") or "").strip()
    question = (d.get("question") or "").strip()
    lang = (d.get("lang") or "en").strip()

    if not provider or not provider_user_id or not question:
        return jsonify(ok=False, message="provider, provider_user_id, question required"), 400

    acct_id = resolve_acct_id(provider, provider_user_id)

    # Rate limit BEFORE calling the AI
    allowed, used, limit = increment_and_check(acct_id)
    if not allowed:
        return jsonify(
            ok=False,
            message=f"Daily limit reached ({used}/{limit}). Please subscribe or try tomorrow.",
            acct_id=acct_id,
            limit=limit,
            used=used
        ), 429

    subscribed = is_paid_active(acct_id)

    log.info("ASK acct=%s provider=%s q=%s", acct_id, provider, question[:200])

    res = resolve_answer(
        wa_phone=acct_id,          # keep param name but acct_id is the real identity
        question=question,
        lang=lang,
        source=provider
    )

    return jsonify(
        ok=True,
        acct_id=acct_id,
        answer=res.get("answer_text") or res.get("message"),
        source=res.get("source"),
        subscribed=subscribed,
        used_today=used,
        daily_limit=limit
    ), 200
