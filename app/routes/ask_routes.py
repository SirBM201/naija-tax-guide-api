# app/routes/ask_routes.py
import os
import time
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, request, jsonify
from app.core.supabase_client import supabase

log = logging.getLogger(__name__)
bp = Blueprint("ask", __name__)

# -----------------------------
# ENV / SETTINGS
# -----------------------------
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()

# Rate limits (safe defaults)
ASK_RL_WINDOW_SEC = int(os.getenv("ASK_RL_WINDOW_SEC", "60"))
ASK_RL_MAX_REQ_PER_WINDOW = int(os.getenv("ASK_RL_MAX_REQ_PER_WINDOW", "20"))

# Optional: relax admin rate limit (default: allow higher)
ASK_RL_ADMIN_MULTIPLIER = int(os.getenv("ASK_RL_ADMIN_MULTIPLIER", "5"))

# Where users should subscribe (frontend)
FRONTEND_BASE_URL = (os.getenv("FRONTEND_BASE_URL") or "").strip()  # e.g. https://thecre8hub.com
SUBSCRIBE_PATH = os.getenv("SUBSCRIBE_PATH", "/pricing").strip() or "/pricing"

# In-memory limiter (single instance)
_rl_bucket: Dict[str, Tuple[float, int]] = {}  # key -> (window_start_ts, count)

# -----------------------------
# Helpers
# -----------------------------
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

def normalize_digits(s: str) -> str:
    return "".join([c for c in (s or "") if c.isdigit()])

def subscribe_url() -> str:
    # Prefer absolute URL if FRONTEND_BASE_URL is set, else relative.
    if FRONTEND_BASE_URL:
        return FRONTEND_BASE_URL.rstrip("/") + (SUBSCRIBE_PATH if SUBSCRIBE_PATH.startswith("/") else f"/{SUBSCRIBE_PATH}")
    return SUBSCRIBE_PATH if SUBSCRIBE_PATH.startswith("/") else f"/{SUBSCRIBE_PATH}"

# -----------------------------
# Admin bypass
# -----------------------------
def is_admin_request() -> bool:
    """
    Admin bypass only when ADMIN_API_KEY is set and matches.
      - x-admin-key: <ADMIN_API_KEY>
      - Authorization: Bearer <ADMIN_API_KEY>
    """
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

# -----------------------------
# Identity -> acct_key
# -----------------------------
def ensure_account(provider: str, provider_user_id: str) -> str:
    """
    Ensures accounts row exists and returns acct_key = acct:<uuid>.
    accounts: { id(uuid), provider(text), provider_user_id(text), phone_e164(text nullable) }
    """
    provider = (provider or "").strip().lower()
    provider_user_id = (provider_user_id or "").strip()

    if provider not in ("wa", "tg", "web"):
        raise ValueError("provider must be wa|tg|web")
    if not provider_user_id:
        raise ValueError("provider_user_id required")

    # Web identities must be digits-only
    if provider == "web":
        provider_user_id = normalize_digits(provider_user_id)

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
        .insert(
            {
                "provider": provider,
                "provider_user_id": provider_user_id,
                "phone_e164": None,
            }
        )
        .execute()
    )
    acct_id = ins.data[0]["id"]
    return f"acct:{acct_id}"

def extract_identity() -> Tuple[str, str]:
    """
    Preferred:
      { "provider": "wa|tg|web", "provider_user_id": "..." }

    Legacy fallback (IMPORTANT FIX):
      { "wa_phone": "234..." } -> treat as web identity digits (because it's not WhatsApp wa_id)
      { "user_key": "234..." } -> treat as web identity digits
    """
    body = request.get_json(silent=True) or {}

    provider = (body.get("provider") or "").strip().lower()
    provider_user_id = (body.get("provider_user_id") or "").strip()

    if provider and provider_user_id:
        if provider == "web":
            provider_user_id = normalize_digits(provider_user_id)
        return provider, provider_user_id

    # ✅ legacy keys are PHONE DIGITS (web identity), not WhatsApp wa_id
    wa_phone = (body.get("wa_phone") or "").strip()
    user_key = (body.get("user_key") or "").strip()

    if wa_phone:
        return "web", normalize_digits(wa_phone)
    if user_key:
        return "web", normalize_digits(user_key)

    return "", ""

# -----------------------------
# Subscription guard (airtight)
# -----------------------------
def get_subscription_status(acct_key: str) -> Tuple[str, Optional[str], Optional[str]]:
    """
    user_subscriptions:
      wa_phone = acct_key (e.g. "acct:<uuid>")
      status = "active"/...
      plan
      expires_at (ISO)

    Truth rules:
      - no row => none
      - malformed expires_at => expired (safer)
      - expires_at <= now => expired
      - expires_at > now AND status in ("active","paid") => active
      - otherwise => none/expired depending on expiry
    """
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
    status = (row.get("status") or "").strip().lower() or "none"
    plan = row.get("plan")
    expires_at = row.get("expires_at")

    # If expires_at is missing, treat as not active unless you explicitly want "lifetime".
    # Safer default: block.
    if not expires_at:
        return "expired", plan, None

    try:
        exp_dt = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        if exp_dt <= now_utc():
            return "expired", plan, str(expires_at)
    except Exception:
        return "expired", plan, str(expires_at)

    # not expired -> must be active/paid
    if status not in ("active", "paid"):
        return status, plan, str(expires_at)

    return "active", plan, str(expires_at)

# -----------------------------
# Rate limiting
# -----------------------------
def rate_limit_key(acct_key: str) -> str:
    ip = (request.headers.get("x-forwarded-for") or request.remote_addr or "unknown").split(",")[0].strip()
    return acct_key or f"ip:{ip}"

def check_rate_limit(key: str, admin_ok: bool) -> Optional[str]:
    """
    In-memory fixed window.
    Admin can get a higher limit via multiplier (default 5x).
    """
    now = time.time()
    win_start, count = _rl_bucket.get(key, (now, 0))

    if now - win_start >= ASK_RL_WINDOW_SEC:
        win_start, count = now, 0

    count += 1
    _rl_bucket[key] = (win_start, count)

    limit = ASK_RL_MAX_REQ_PER_WINDOW * (ASK_RL_ADMIN_MULTIPLIER if admin_ok else 1)
    if count > limit:
        return "Too many requests. Please wait and try again."
    return None

# -----------------------------
# Your AI service hook
# -----------------------------
def run_ai_answer(question: str, acct_key: str) -> Dict[str, Any]:
    """
    Replace with your pipeline.
    Must return: { "answer": "..." }
    """
    return {"answer": f"(demo) You asked: {question}", "acct_key": acct_key}

# -----------------------------
# POST /ask
# -----------------------------
@bp.post("/ask")
def ask():
    body = request.get_json(silent=True) or {}
    question = (body.get("question") or body.get("q") or "").strip()

    if not question or len(question) < 2:
        return json_error("Question is required.", 400)

    # 1) Identity
    provider, provider_user_id = extract_identity()
    if not provider or not provider_user_id:
        return json_error(
            "Identity required. Send provider + provider_user_id (recommended).",
            400,
            example={"provider": "wa", "provider_user_id": "2348012345678"},
        )

    try:
        acct_key = ensure_account(provider, provider_user_id)
    except Exception as e:
        log.exception("ensure_account failed")
        return json_error("Unable to process identity.", 400, detail=str(e))

    # 2) Admin bypass
    admin_ok = is_admin_request()

    # 3) Subscription guard (block everything except admin)
    if not admin_ok:
        status, plan, expires_at = get_subscription_status(acct_key)
        if status != "active":
            return json_error(
                "Subscription required or expired.",
                403,
                status=status,
                plan=plan,
                expires_at=expires_at,
                subscribe_url=subscribe_url(),
            )

    # 4) Rate limiting (admin gets higher limit)
    key = rate_limit_key(acct_key)
    msg = check_rate_limit(key, admin_ok=admin_ok)
    if msg:
        return json_error(msg, 429)

    # 5) Run AI
    try:
        out = run_ai_answer(question=question, acct_key=acct_key)
        answer = out.get("answer")
        if not answer:
            return json_error("AI returned empty response.", 502)

        return json_ok(
            answer=answer,
            acct_key=acct_key,
            provider=provider,
            provider_user_id=provider_user_id,
        )
    except Exception as e:
        log.exception("AI ask failed")
        return json_error("AI service error.", 500, detail=str(e))
