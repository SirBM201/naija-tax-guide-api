# app/routes/ask_routes.py
import os
import time
import logging
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase
from app.services.ai import generate_answer

log = logging.getLogger(__name__)
bp = Blueprint("ask", __name__)

ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY") or "").strip()

ASK_RL_WINDOW_SEC = int(os.getenv("ASK_RL_WINDOW_SEC", "60"))
ASK_RL_MAX_REQ_PER_WINDOW = int(os.getenv("ASK_RL_MAX_REQ_PER_WINDOW", "20"))

_rl_bucket: Dict[str, Tuple[float, int]] = {}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ✅ IMPORTANT: do NOT use parameter name "status"
def json_error(message: str, http_code: int = 400, **extra):
    payload = {"ok": False, "message": message}
    payload.update(extra)
    return jsonify(payload), http_code


def json_ok(**data):
    payload = {"ok": True}
    payload.update(data)
    return jsonify(payload), 200


def normalize_digits(s: str) -> str:
    return "".join([c for c in (s or "") if c.isdigit()])


def is_admin_request() -> bool:
    if not ADMIN_API_KEY:
        return False

    x = (request.headers.get("x-admin-key") or "").strip()
    if x and x == ADMIN_API_KEY:
        return True

    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
        return token == ADMIN_API_KEY

    return False


def extract_identity(body: dict) -> Tuple[str, str]:
    provider = (body.get("provider") or "").strip().lower()
    provider_user_id = (body.get("provider_user_id") or "").strip()

    if provider and provider_user_id:
        if provider == "web":
            provider_user_id = normalize_digits(provider_user_id)
        return provider, provider_user_id

    wa_phone = (body.get("wa_phone") or "").strip()
    user_key = (body.get("user_key") or "").strip()

    if wa_phone:
        return "wa", normalize_digits(wa_phone)
    if user_key:
        return "wa", normalize_digits(user_key)

    return "", ""


def ensure_account(provider: str, provider_user_id: str) -> str:
    provider = (provider or "").strip().lower()
    provider_user_id = (provider_user_id or "").strip()

    if provider not in ("wa", "tg", "web"):
        raise ValueError("provider must be wa|tg|web")
    if not provider_user_id:
        raise ValueError("provider_user_id required")

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
    if rows:
        return f"acct:{rows[0]['id']}"

    ins = (
        supabase()
        .table("accounts")
        .insert(
            {
                "provider": provider,
                "provider_user_id": provider_user_id,
                "phone_e164": None,
            }
        )
        .execute()
    )
    created = getattr(ins, "data", None) or []
    if not created or not created[0].get("id"):
        raise RuntimeError("Failed to create account row")
    return f"acct:{created[0]['id']}"


def get_subscription_status(acct_key: str) -> Tuple[str, Optional[str], Optional[str]]:
    r = (
        supabase()
        .table("user_subscriptions")
        .select("status,plan,expires_at")
        .eq("wa_phone", acct_key)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if not rows:
        return "none", None, None

    row = rows[0]
    sub_status = (row.get("status") or "").strip().lower() or "none"
    plan = row.get("plan")
    expires_at = row.get("expires_at")

    if expires_at:
        try:
            exp_dt = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            if exp_dt <= now_utc():
                return "expired", plan, str(expires_at)
        except Exception:
            return "expired", plan, str(expires_at)

    if sub_status != "active":
        return sub_status, plan, str(expires_at) if expires_at else None

    return "active", plan, str(expires_at) if expires_at else None


def rate_limit_key(acct_key: str) -> str:
    ip = (request.headers.get("x-forwarded-for") or request.remote_addr or "unknown").split(",")[0].strip()
    return acct_key or f"ip:{ip}"


def check_rate_limit(key: str) -> Optional[str]:
    now = time.time()
    win_start, count = _rl_bucket.get(key, (now, 0))

    if now - win_start >= ASK_RL_WINDOW_SEC:
        win_start, count = now, 0

    count += 1
    _rl_bucket[key] = (win_start, count)

    if count > ASK_RL_MAX_REQ_PER_WINDOW:
        return "Too many requests. Please wait and try again."
    return None


def run_ai_answer(question: str, lang: str) -> str:
    ans = generate_answer(question=question, lang=lang)
    return ans or "Sorry, AI service is temporarily unavailable. Please try again shortly."


@bp.post("/ask")
def ask():
    body = request.get_json(silent=True) or {}

    question = (body.get("question") or body.get("q") or "").strip()
    mode = (body.get("mode") or "text").strip()
    lang = (body.get("lang") or "en").strip()

    if not question or len(question) < 2:
        return json_error("Question is required.", http_code=400)

    provider, provider_user_id = extract_identity(body)
    if not provider or not provider_user_id:
        return json_error(
            "Identity required. Send provider + provider_user_id.",
            http_code=400,
            example={"provider": "web", "provider_user_id": "2348012345678"},
        )

    try:
        acct_key = ensure_account(provider, provider_user_id)
    except Exception as e:
        log.exception("ensure_account failed")
        return json_error("Unable to process identity.", http_code=400, detail=str(e))

    admin_ok = is_admin_request()

    sub_status, plan, expires_at = get_subscription_status(acct_key)
    if not admin_ok and sub_status != "active":
        # ✅ IMPORTANT: we can now safely include "status" in payload
        return json_error(
            "Subscription required or expired.",
            http_code=403,
            status=sub_status,
            plan=plan,
            expires_at=expires_at,
            subscribe_url="/pricing",
        )

    msg = check_rate_limit(rate_limit_key(acct_key))
    if msg:
        return json_error(msg, http_code=429)

    try:
        answer = run_ai_answer(question=question, lang=lang)
        return json_ok(
            answer=answer,
            audio_url=None,
            provider=provider,
            provider_user_id=provider_user_id,
            acct_key=acct_key,
            plan=plan,
            expires_at=expires_at,
            admin=admin_ok,
            mode=mode,
            lang=lang,
        )
    except Exception as e:
        log.exception("AI ask failed")
        return json_error("AI service error.", http_code=500, detail=str(e))
