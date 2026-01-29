# app/routes/ask.py
from flask import Blueprint, request, jsonify
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.services.engine import resolve_answer
from app.db.supabase_client import supabase  # NOTE: this is the client object (NOT a function)

bp = Blueprint("ask", __name__)


# -----------------------------
# Helpers
# -----------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_phone_digits(p: str) -> str:
    return "".join(ch for ch in (p or "").strip() if ch.isdigit())


def _normalize_provider(p: str) -> str:
    p = (p or "").strip().lower()
    if p in ("wa", "whatsapp"):
        return "wa"
    if p in ("tg", "telegram"):
        return "tg"
    if p in ("web", "site", "browser"):
        return "web"
    return p or "web"


def _resolve_acct_id(provider: str, provider_user_id: str, phone_e164: Optional[str] = None) -> str:
    """
    Accounts table only (no Supabase Auth).
    We store channel identity in public.accounts(provider, provider_user_id).
    Returns accounts.id (uuid as string).
    """
    provider = _normalize_provider(provider)
    provider_user_id = (provider_user_id or "").strip()

    if not provider_user_id:
        raise ValueError("provider_user_id is required")

    # 1) lookup existing
    r = (
        supabase
        .table("accounts")
        .select("id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if rows:
        return str(rows[0]["id"])

    # 2) create (minimal)
    payload = {
        "provider": provider,
        "provider_user_id": provider_user_id,
        "status": "active",
        "updated_at": _now_utc().isoformat(),
    }
    if phone_e164:
        payload["phone_e164"] = phone_e164[:40]

    ins = supabase.table("accounts").insert(payload).execute()
    created = getattr(ins, "data", None) or []
    if created and created[0].get("id"):
        return str(created[0]["id"])

    # 3) fallback: re-read (handles race/unique constraint)
    r2 = (
        supabase
        .table("accounts")
        .select("id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    rows2 = getattr(r2, "data", None) or []
    if rows2:
        return str(rows2[0]["id"])

    raise RuntimeError("Failed to resolve account id")


def _acct_key(acct_id: str) -> str:
    return f"acct:{acct_id}"


def _get_subscription(acct_key: str) -> Optional[Dict[str, Any]]:
    """
    For now we store the unified identity inside user_subscriptions.wa_phone
    Example: wa_phone = "acct:<uuid>"
    """
    try:
        r = (
            supabase
            .table("user_subscriptions")
            .select("*")
            .eq("wa_phone", acct_key)
            .limit(1)
            .execute()
        )
        rows = getattr(r, "data", None) or []
        return rows[0] if rows else None
    except Exception as e:
        logging.exception("subscription lookup failed: %s", e)
        return None


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


# -----------------------------
# ASK (AI)
# -----------------------------
@bp.post("/ask")
def ask():
    """
    Accepts BOTH formats:

    A) New (recommended):
      {
        "provider": "web" | "wa" | "tg",
        "provider_user_id": "<unique id per channel>",
        "question": "...",
        "mode": "text" | "voice",
        "lang": "en" | "pcm" | "yo" | "ig" | "ha"
      }

    B) Old (backward compatible):
      {
        "wa_phone": "2348012345678" or "user_key": "...",
        "question": "..."
      }
    """
    data = request.get_json(silent=True) or {}

    question = str(data.get("question") or data.get("text") or "").strip()
    mode = str(data.get("mode") or "text").strip()
    lang = str(data.get("lang") or "en").strip()

    provider = (data.get("provider") or "").strip()
    provider_user_id = (data.get("provider_user_id") or "").strip()

    # Old format fallback
    raw_key = str(data.get("wa_phone") or data.get("user_key") or "").strip()
    phone_digits = _normalize_phone_digits(raw_key)

    if not question:
        return jsonify({"ok": False, "message": "question is required"}), 400

    # Decide identity source
    if provider and provider_user_id:
        provider_norm = _normalize_provider(provider)
        acct_id = _resolve_acct_id(provider_norm, provider_user_id, phone_e164=None)
        source = provider_norm
        provider_debug = provider_norm
        provider_user_debug = provider_user_id
    else:
        # Old style: treat as web identity using phone digits
        if not phone_digits:
            return jsonify({"ok": False, "message": "provider+provider_user_id OR wa_phone/user_key is required"}), 400
        acct_id = _resolve_acct_id("web", phone_digits, phone_e164=phone_digits)
        source = "web"
        provider_debug = "web"
        provider_user_debug = phone_digits

    acct_key = _acct_key(acct_id)

    # optional subscription info (for UI plan expiry display)
    sub = _get_subscription(acct_key)
    active = _is_active(sub)
    plan_expiry = sub.get("expires_at") if sub else None

    logging.info(
        "ASK acct_key=%s active=%s provider=%s provider_user_id=%s lang=%s mode=%s q=%s",
        acct_key,
        active,
        provider_debug,
        provider_user_debug,
        lang,
        mode,
        question[:200],
    )

    # IMPORTANT: we pass acct_key into engine identity
    res = resolve_answer(
        wa_phone=acct_key,  # engine expects a string identity; name kept for compatibility
        question=question,
        mode=mode,
        lang=lang,
        source=source,
    )

    # If engine blocks (quota), return ok=false properly
    if not res.get("ok", True):
        return jsonify(
            {
                "ok": False,
                "message": res.get("message") or "Blocked",
                "reason": res.get("reason"),
                "action": res.get("action"),
                "plan_expiry": plan_expiry,
                "acct_id": acct_id,
                "acct_key": acct_key,
            }
        ), 403

    return jsonify(
        {
            "ok": True,
            "answer": res.get("answer_text"),
            "audio_url": res.get("audio_url"),
            "plan_expiry": plan_expiry,
            "source": res.get("source"),
            "acct_id": acct_id,
            "acct_key": acct_key,
        }
    ), 200
