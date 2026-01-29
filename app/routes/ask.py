# app/routes/ask.py
from flask import Blueprint, request, jsonify
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.services.engine import resolve_answer
from app.db.supabase_client import supabase  # FUNCTION -> use supabase().table(...)

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


def _resolve_account_id(provider: str, provider_user_id: str, phone_e164: Optional[str] = None) -> str:
    """
    Uses public.accounts (NO Supabase Auth).
    Table columns confirmed: id, provider, provider_user_id, phone_e164, created_at, updated_at
    Returns accounts.id (uuid as string).
    """
    provider = _normalize_provider(provider)
    provider_user_id = (provider_user_id or "").strip()

    if not provider_user_id:
        raise ValueError("provider_user_id is required")

    # 1) lookup existing
    r = (
        supabase()
        .table("accounts")
        .select("id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if rows and rows[0].get("id"):
        return str(rows[0]["id"])

    # 2) create minimal account row
    payload = {
        "provider": provider,
        "provider_user_id": provider_user_id,
        "updated_at": _now_utc().isoformat(),
    }
    if phone_e164:
        payload["phone_e164"] = phone_e164[:40]

    ins = supabase().table("accounts").insert(payload).execute()
    created = getattr(ins, "data", None) or []
    if created and created[0].get("id"):
        return str(created[0]["id"])

    # 3) fallback re-read (handles race/unique constraint)
    r2 = (
        supabase()
        .table("accounts")
        .select("id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    rows2 = getattr(r2, "data", None) or []
    if rows2 and rows2[0].get("id"):
        return str(rows2[0]["id"])

    raise RuntimeError("Failed to resolve accounts.id")


def _acct_key(account_id: str) -> str:
    return f"acct:{account_id}"


def _get_subscription(acct_key: str) -> Optional[Dict[str, Any]]:
    """
    user_subscriptions.wa_phone stores unified identity: "acct:<uuid>"
    """
    try:
        r = (
            supabase()
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
# ASK
# -----------------------------
@bp.post("/ask")
def ask():
    """
    Accepts BOTH formats:

    A) New:
      {
        "provider": "web" | "wa" | "tg",
        "provider_user_id": "<unique id per channel>",
        "question": "...",
        "mode": "text" | "voice",
        "lang": "en" | "pcm" | "yo" | "ig" | "ha"
      }

    B) Old:
      { "wa_phone": "2348012345678", "question": "..." }
    """
    data = request.get_json(silent=True) or {}

    question = str(data.get("question") or data.get("text") or "").strip()
    mode = str(data.get("mode") or "text").strip()
    lang = str(data.get("lang") or "en").strip()

    provider = (data.get("provider") or "").strip()
    provider_user_id = (data.get("provider_user_id") or "").strip()

    raw_key = str(data.get("wa_phone") or data.get("user_key") or "").strip()
    phone_digits = _normalize_phone_digits(raw_key)

    if not question:
        return jsonify({"ok": False, "message": "question is required"}), 400

    # Resolve account id
    if provider and provider_user_id:
        provider_norm = _normalize_provider(provider)
        account_id = _resolve_account_id(provider_norm, provider_user_id, phone_e164=None)
    else:
        # Old style => treat as web identity (phone digits)
        if not phone_digits:
            return jsonify({"ok": False, "message": "provider+provider_user_id OR wa_phone/user_key is required"}), 400
        account_id = _resolve_account_id("web", phone_digits, phone_e164=phone_digits)

    acct_key = _acct_key(account_id)

    # subscription for UI plan expiry display
    sub = _get_subscription(acct_key)
    plan_expiry = sub.get("expires_at") if sub else None
    active = _is_active(sub)

    logging.info(
        "ASK acct_key=%s active=%s provider=%s provider_user_id=%s lang=%s mode=%s q=%s",
        acct_key,
        active,
        provider or "web",
        provider_user_id or phone_digits,
        lang,
        mode,
        question[:200],
    )

    # Engine identity is acct_key (string)
    res = resolve_answer(
        wa_phone=acct_key,
        question=question,
        mode=mode,
        lang=lang,
        source=(provider or "web") or "web",
    )

    if not res.get("ok", True):
        return jsonify(
            {
                "ok": False,
                "message": res.get("message") or "Blocked",
                "reason": res.get("reason"),
                "action": res.get("action"),
                "plan_expiry": plan_expiry,
                "account_id": account_id,
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
            "account_id": account_id,
            "acct_key": acct_key,
        }
    ), 200
