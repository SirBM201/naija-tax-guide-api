# app/routes/ask_routes.py
import os
import time
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase
from app.ai.generate_answer import generate_answer  # 👈 your OpenAI pipeline

log = logging.getLogger(__name__)
bp = Blueprint("ask", __name__)

# -------------------------------------------------
# ENV / SETTINGS
# -------------------------------------------------
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()

ASK_RL_WINDOW_SEC = int(os.getenv("ASK_RL_WINDOW_SEC", "60"))
ASK_RL_MAX_REQ_PER_WINDOW = int(os.getenv("ASK_RL_MAX_REQ_PER_WINDOW", "20"))

# simple in-memory rate limit bucket (safe + lightweight)
_rl_bucket: Dict[str, Tuple[float, int]] = {}

# -------------------------------------------------
# Helpers
# -------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def json_error(message: str, status: int = 400, **extra):
    payload = {"ok": False, "message": message}
    payload.update(extra)
    return jsonify(payload), status

def json_ok(**data):
    payload = {"ok": True}
    payload.update(data)
    return jsonify(payload), 200

# -------------------------------------------------
# Admin bypass
# -------------------------------------------------
def is_admin_request() -> bool:
    """
    Admin bypass via:
      - x-admin-key
      - Authorization: Bearer <ADMIN_API_KEY>
    """
    if not ADMIN_API_KEY:
        return False

    if request.headers.get("x-admin-key", "").strip() == ADMIN_API_KEY:
        return True

    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip() == ADMIN_API_KEY

    return False

# -------------------------------------------------
# Identity handling
# -------------------------------------------------
def normalize_digits(s: str) -> str:
    return "".join(c for c in (s or "") if c.isdigit())

def extract_identity() -> Tuple[str, str]:
    """
    Accepts:
      NEW:
        { provider, provider_user_id }
      LEGACY:
        { wa_phone } | { user_key }
    """
    body = request.get_json(silent=True) or {}

    provider = (body.get("provider") or "").strip().lower()
    provider_user_id = (body.get("provider_user_id") or "").strip()

    if provider and provider_user_id:
        if provider == "web":
            provider_user_id = normalize_digits(provider_user_id)
        return provider, provider_user_id

    # legacy support
    if body.get("wa_phone"):
        return "wa", normalize_digits(body["wa_phone"])
    if body.get("user_key"):
        return "wa", normalize_digits(body["user_key"])

    return "", ""

def ensure_account(provider: str, provider_user_id: str) -> str:
    """
    Ensures accounts row exists.
    Returns acct_key = acct:<uuid>
    """
    provider = provider.lower().strip()

    r = (
        supabase()
        .table("accounts")
        .select("id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    if r.data:
        return f"acct:{r.data[0]['id']}"

    ins = (
        supabase()
        .table("accounts")
        .insert({
            "provider": provider,
            "provider_user_id": provider_user_id,
            "phone_e164": None,
        })
        .execute()
    )
    return f"acct:{ins.data[0]['id']}"

# -------------------------------------------------
# Subscription guard (authoritative)
# -------------------------------------------------
def get_subscription_status(acct_key: str) -> Tuple[str, Optional[str], Optional[str]]:
    r = (
        supabase()
        .table("user_subscriptions")
        .select("status,plan,expires_at")
        .eq("wa_phone", acct_key)
        .limit(1)
        .execute()
    )

    if not r.data:
        return "none", None, None

    row = r.data[0]
    status = (row.get("status") or "").lower()
    plan = row.get("plan")
    expires_at = row.get("expires_at")

    if expires_at:
        try:
            exp_dt = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            if exp_dt <= now_utc():
                return "expired", plan, expires_at
        except Exception:
            return "expired", plan, expires_at

    if status != "active":
        return status or "none", plan, expires_at

    return "active", plan, expires_at

# -------------------------------------------------
# Rate limiting
# -------------------------------------------------
def rate_limit_key(acct_key: str) -> str:
    ip = (request.headers.get("x-forwarded-for") or request.remote_addr or "unknown")
    return acct_key or f"ip:{ip}"

def check_rate_limit(key: str) -> Optional[str]:
    now = time.time()
    win_start, count = _rl_bucket.get(key, (now, 0))

    if now - win_start >= ASK_RL_WINDOW_SEC:
        win_start, count = now, 0

    count += 1
    _rl_bucket[key] = (win_start, count)

    if count > ASK_RL_MAX_REQ_PER_WINDOW:
        return "Too many requests. Please slow down."
    return None

# -------------------------------------------------
# POST /ask
# -------------------------------------------------
@bp.post("/ask")
def ask():
    body = request.get_json(silent=True) or {}
    question = (body.get("question") or body.get("q") or "").strip()
    lang = (body.get("lang") or "en").strip()

    if len(question) < 2:
        return json_error("Question is required.", 400)

    # 1) Identity
    provider, provider_user_id = extract_identity()
    if not provider or not provider_user_id:
        return json_error(
            "Identity required.",
            400,
            example={"provider": "wa", "provider_user_id": "2348012345678"},
        )

    try:
        acct_key = ensure_account(provider, provider_user_id)
    except Exception as e:
        log.exception("ensure_account failed")
        return json_error("Unable to resolve identity.", 400, detail=str(e))

    # 2) Admin bypass
    admin_ok = is_admin_request()

    # 3) Subscription enforcement
    if not admin_ok:
        status, plan, expires_at = get_subscription_status(acct_key)
        if status != "active":
            return json_error(
                "Subscription required or expired.",
                403,
                status=status,
                plan=plan,
                expires_at=expires_at,
                subscribe_url="/pricing",
            )

    # 4) Rate limit
    msg = check_rate_limit(rate_limit_key(acct_key))
    if msg:
        return json_error(msg, 429)

    # 5) AI pipeline
    try:
        answer = generate_answer(question=question, lang=lang)
        if not answer:
            return json_error("AI service unavailable.", 503)

        return json_ok(
            answer=answer,
            provider=provider,
            provider_user_id=provider_user_id,
            acct_key=acct_key,
        )
    except Exception as e:
        log.exception("AI pipeline failed")
        return json_error("AI service error.", 500, detail=str(e))
