# app/routes/ask_routes.py
import os
import time
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase

log = logging.getLogger(__name__)
bp = Blueprint("ask", __name__)  # blueprint name

# -----------------------------
# ENV / SETTINGS
# -----------------------------
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()

# basic rate limits (safe defaults)
# You can tune later:
# - FREE users should never pass subscription guard anyway
# - So these mostly protect from abuse + bugs.
ASK_RL_WINDOW_SEC = int(os.getenv("ASK_RL_WINDOW_SEC", "60"))
ASK_RL_MAX_REQ_PER_WINDOW = int(os.getenv("ASK_RL_MAX_REQ_PER_WINDOW", "20"))

# optional: if you store usage in DB (recommended later)
USE_DB_RATE_LIMIT = (os.getenv("USE_DB_RATE_LIMIT", "0").strip() == "1")

# In-memory limiter (works on a single instance).
# Koyeb can restart/deep sleep => memory resets (fine as basic protection).
_rl_bucket: Dict[str, Tuple[float, int]] = {}  # key -> (window_start_ts, count)


# -----------------------------
# Helpers: time / response
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


# -----------------------------
# Admin bypass (safe)
# -----------------------------
def is_admin_request() -> bool:
    """
    Admin bypass is allowed ONLY when ADMIN_API_KEY is set and matches.
    Accepted:
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
def normalize_digits(s: str) -> str:
    return "".join([c for c in (s or "") if c.isdigit()])

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
    acct_id = ins.data[0]["id"]
    return f"acct:{acct_id}"


def extract_identity() -> Tuple[str, str]:
    """
    Accepts identity in either:
      A) unified format (recommended):
         { "provider": "wa|tg|web", "provider_user_id": "..." }
      B) legacy format:
         { "wa_phone": "234..." }  -> treated as provider="wa"
         { "user_key": "234..." }  -> treated as provider="wa" (because you are using phone digits)
    """
    body = request.get_json(silent=True) or {}

    provider = (body.get("provider") or "").strip().lower()
    provider_user_id = (body.get("provider_user_id") or "").strip()

    if provider and provider_user_id:
        if provider == "web":
            provider_user_id = normalize_digits(provider_user_id)
        return provider, provider_user_id

    # fallback legacy keys (your app used these earlier)
    wa_phone = (body.get("wa_phone") or "").strip()
    user_key = (body.get("user_key") or "").strip()

    if wa_phone:
        return "wa", normalize_digits(wa_phone)
    if user_key:
        return "wa", normalize_digits(user_key)

    return "", ""


# -----------------------------
# Subscription guard (airtight)
# -----------------------------
def get_subscription_status(acct_key: str) -> Tuple[str, Optional[str], Optional[str]]:
    """
    user_subscriptions table (your convention):
      wa_phone = acct_key (e.g. "acct:<uuid>")
      status = "active"/"expired"/...
      plan
      expires_at (ISO)
    Returns: (status, plan, expires_at)
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
    status = (row.get("status") or "").lower() or "none"
    plan = row.get("plan")
    expires_at = row.get("expires_at")

    # expiry truth wins even if status says active
    if expires_at:
        try:
            exp_dt = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            if exp_dt <= now_utc():
                return "expired", plan, str(expires_at)
        except Exception:
            # if expires_at is malformed, treat as expired (safer)
            return "expired", plan, str(expires_at)

    if status != "active":
        # status not active -> block
        return status, plan, str(expires_at) if expires_at else None

    return "active", plan, str(expires_at) if expires_at else None


# -----------------------------
# Rate limiting (clean + safe)
# -----------------------------
def rate_limit_key(acct_key: str) -> str:
    # Use acct_key if present; fallback to IP (so anonymous abuse is still controlled).
    ip = (request.headers.get("x-forwarded-for") or request.remote_addr or "unknown").split(",")[0].strip()
    return acct_key or f"ip:{ip}"

def check_rate_limit(key: str) -> Optional[str]:
    """
    Returns None if allowed, else returns human-friendly error message.
    """
    now = time.time()
    win_start, count = _rl_bucket.get(key, (now, 0))

    if now - win_start >= ASK_RL_WINDOW_SEC:
        win_start, count = now, 0

    count += 1
    _rl_bucket[key] = (win_start, count)

    if count > ASK_RL_MAX_REQ_PER_WINDOW:
        return f"Too many requests. Please wait and try again."
    return None


# -----------------------------
# Your AI "ask" service hook
# -----------------------------
def run_ai_answer(question: str, acct_key: str) -> Dict[str, Any]:
    """
    🔧 Replace this with your existing AI pipeline.
    Keep this interface:
      input: (question, acct_key)
      output: { "answer": "...", "source": "...", ... }
    """
    # Example placeholder:
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
            example={"provider": "wa", "provider_user_id": "2348012345678"}
        )

    try:
        acct_key = ensure_account(provider, provider_user_id)
    except Exception as e:
        log.exception("ensure_account failed")
        return json_error("Unable to process identity.", 400, detail=str(e))

    # 2) Admin bypass
    admin_ok = is_admin_request()

    # 3) Subscription guard (airtight)
    if not admin_ok:
        status, plan, expires_at = get_subscription_status(acct_key)
        if status != "active":
            return json_error(
                "Subscription required or expired.",
                403,
                status=status,
                plan=plan,
                expires_at=expires_at,
                subscribe_url="/pricing"
            )

    # 4) Rate limiting (applies to BOTH admin + users, but you can relax admin if you want)
    rl_key = rate_limit_key(acct_key)
    msg = check_rate_limit(rl_key)
    if msg:
        return json_error(msg, 429)

    # 5) Run AI
    try:
        out = run_ai_answer(question=question, acct_key=acct_key)
        return json_ok(
            answer=out.get("answer"),
            acct_key=acct_key,
            provider=provider,
            provider_user_id=provider_user_id
        )
    except Exception as e:
        log.exception("AI ask failed")
        return json_error("AI service error.", 500, detail=str(e))
