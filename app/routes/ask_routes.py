# app/routes/ask_routes.py
import os
import time
import logging
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import requests
from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase

log = logging.getLogger(__name__)
bp = Blueprint("ask", __name__)

# -----------------------------------
# ENV
# -----------------------------------
ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY") or "").strip()

OPENAI_API_KEY = (os.getenv("OPENAI_API_KEY") or "").strip()
OPENAI_MODEL = (os.getenv("OPENAI_MODEL") or "gpt-4o-mini").strip()
OPENAI_BASE_URL = (os.getenv("OPENAI_BASE_URL") or "https://api.openai.com/v1").strip()

# Rate limit settings (safe defaults)
ASK_RL_WINDOW_SEC = int(os.getenv("ASK_RL_WINDOW_SEC", "60"))
ASK_RL_MAX_REQ_PER_WINDOW = int(os.getenv("ASK_RL_MAX_REQ_PER_WINDOW", "20"))

# If you want admin to bypass rate limiting:
ADMIN_BYPASS_RATE_LIMIT = (os.getenv("ADMIN_BYPASS_RATE_LIMIT", "0").strip() == "1")

# In-memory rate limiter (good basic protection)
# key -> (window_start_ts, count, last_seen_ts)
_rl_bucket: Dict[str, Tuple[float, int, float]] = {}
_rl_max_keys = int(os.getenv("ASK_RL_MAX_KEYS", "5000"))  # cap memory
_rl_gc_every = int(os.getenv("ASK_RL_GC_EVERY", "200"))    # cleanup cadence
_rl_ops = 0


# -----------------------------------
# Helpers: time / JSON
# -----------------------------------
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


# -----------------------------------
# Admin bypass
# -----------------------------------
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


# -----------------------------------
# Identity -> acct_key
# -----------------------------------
def ensure_account(provider: str, provider_user_id: str) -> Tuple[str, str]:
    """
    Ensures accounts row exists and returns:
      (acct_id, acct_key="acct:<uuid>")

    accounts expected columns:
      id (uuid primary key)
      provider (text)
      provider_user_id (text)
    """
    provider = (provider or "").strip().lower()
    provider_user_id = (provider_user_id or "").strip()

    if provider not in ("wa", "tg", "web"):
        raise ValueError("provider must be wa|tg|web")
    if not provider_user_id:
        raise ValueError("provider_user_id required")

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
    if getattr(r, "data", None):
        acct_id = str(r.data[0]["id"])
        return acct_id, f"acct:{acct_id}"

    ins = (
        supabase()
        .table("accounts")
        .insert({
            "provider": provider,
            "provider_user_id": provider_user_id,
        })
        .execute()
    )

    acct_id = str(ins.data[0]["id"])
    return acct_id, f"acct:{acct_id}"


def extract_identity(body: dict) -> Tuple[str, str]:
    """
    Preferred:
      { "provider": "wa|tg|web", "provider_user_id": "..." }

    Legacy fallback:
      { "wa_phone": "234..." }  -> provider="wa"
      { "user_key": "234..." }  -> provider="wa"
    """
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


# -----------------------------------
# Subscription guard (airtight)
# -----------------------------------
def get_subscription_status(acct_key: str) -> Tuple[str, Optional[str], Optional[str]]:
    """
    user_subscriptions expected:
      wa_phone (text primary key)  <-- stores acct_key like "acct:<uuid>"
      status (text) e.g. "active"
      plan (text) e.g. "monthly"
      expires_at (timestamptz)

    Rules:
      - If expires_at <= now => expired (even if status says active)
      - If status != active => not allowed
      - If expires_at missing => treat as expired (safer)
    """
    r = (
        supabase()
        .table("user_subscriptions")
        .select("status,plan,expires_at,paystack_reference")
        .eq("wa_phone", acct_key)
        .limit(1)
        .execute()
    )

    rows = getattr(r, "data", None) or []
    if not rows:
        return "none", None, None

    row = rows[0]
    status = (row.get("status") or "").strip().lower() or "none"
    plan = row.get("plan")
    expires_at = row.get("expires_at")

    if not expires_at:
        # safer: don't allow "permanent active" due to missing expiry
        return "expired", plan, None

    try:
        exp_dt = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        if exp_dt <= now_utc():
            return "expired", plan, str(expires_at)
    except Exception:
        return "expired", plan, str(expires_at)

    if status != "active":
        return status, plan, str(expires_at)

    return "active", plan, str(expires_at)


# -----------------------------------
# Rate limiting (clean)
# -----------------------------------
def _client_ip() -> str:
    ip = (request.headers.get("x-forwarded-for") or request.remote_addr or "unknown")
    return ip.split(",")[0].strip()

def rate_limit_key(acct_key: str) -> str:
    # Prefer acct_key; fallback to IP if anything missing.
    return acct_key or f"ip:{_client_ip()}"

def _rl_gc(now: float) -> None:
    """
    Cleanup old keys to prevent unbounded growth.
    """
    # Remove keys not seen for 2 windows
    cutoff = now - (ASK_RL_WINDOW_SEC * 2)
    dead = [k for k, (_, __, last_seen) in _rl_bucket.items() if last_seen < cutoff]
    for k in dead:
        _rl_bucket.pop(k, None)

    # Hard cap if still too big
    if len(_rl_bucket) > _rl_max_keys:
        # drop oldest by last_seen
        items = sorted(_rl_bucket.items(), key=lambda kv: kv[1][2])  # oldest first
        for k, _v in items[: max(0, len(_rl_bucket) - _rl_max_keys)]:
            _rl_bucket.pop(k, None)

def check_rate_limit(key: str) -> Optional[str]:
    """
    Returns None if allowed, else returns error message.
    """
    global _rl_ops
    _rl_ops += 1

    now = time.time()
    if (_rl_ops % _rl_gc_every) == 0:
        _rl_gc(now)

    win_start, count, _last = _rl_bucket.get(key, (now, 0, now))

    # reset window
    if now - win_start >= ASK_RL_WINDOW_SEC:
        win_start, count = now, 0

    count += 1
    _rl_bucket[key] = (win_start, count, now)

    if count > ASK_RL_MAX_REQ_PER_WINDOW:
        return "Too many requests. Please wait and try again."
    return None


# -----------------------------------
# AI pipeline (raw HTTPS, no python openai package)
# -----------------------------------
def generate_answer(question: str, lang: str = "en") -> Optional[str]:
    if not OPENAI_API_KEY:
        log.warning("AI disabled: OPENAI_API_KEY not set")
        return None

    q = (question or "").strip()
    if not q:
        return None

    system = (
        "You are Naija Tax Guide. Give accurate Nigeria-focused tax guidance. "
        "Be clear and structured. Use short headings and bullets. "
        "If uncertain, say so and suggest checking FIRS or a tax professional."
    )

    payload = {
        "model": OPENAI_MODEL,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": f"Language={lang}\n\nQuestion: {q}"},
        ],
    }

    try:
        r = requests.post(
            f"{OPENAI_BASE_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=25,
        )

        if r.status_code >= 400:
            log.warning("OpenAI error %s: %s", r.status_code, r.text[:300])
            return None

        data = r.json()
        text = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )
        return text or None
    except Exception as e:
        log.exception("OpenAI request failed: %s", e)
        return None


# -----------------------------------
# POST /ask
# -----------------------------------
@bp.post("/ask")
def ask():
    body = request.get_json(silent=True) or {}

    question = (body.get("question") or body.get("q") or "").strip()
    mode = (body.get("mode") or "text").strip().lower()
    lang = (body.get("lang") or "en").strip().lower()

    if not question or len(question) < 2:
        return json_error("Question is required.", 400)

    # 1) Identity (required)
    provider, provider_user_id = extract_identity(body)
    if not provider or not provider_user_id:
        return json_error(
            "Identity required. Send provider + provider_user_id.",
            400,
            example={"provider": "wa", "provider_user_id": "2348012345678"}
        )

    try:
        acct_id, acct_key = ensure_account(provider, provider_user_id)
    except Exception as e:
        log.exception("ensure_account failed")
        return json_error("Unable to process identity.", 400, detail=str(e))

    # 2) Admin bypass
    admin_ok = is_admin_request()

    # 3) Subscription guard (strict)
    status, plan, expires_at = get_subscription_status(acct_key)
    if not admin_ok:
        if status != "active":
            return json_error(
                "Subscription required or expired.",
                403,
                status=status,
                plan=plan,
                expires_at=expires_at,
                subscribe_url="/pricing"
            )

    # 4) Rate limiting
    if not (admin_ok and ADMIN_BYPASS_RATE_LIMIT):
        rl_key = rate_limit_key(acct_key)
        msg = check_rate_limit(rl_key)
        if msg:
            return json_error(msg, 429)

    # 5) Run AI
    answer = generate_answer(question=question, lang=lang)
    if not answer:
        return json_error("AI temporarily unavailable. Please try again.", 503)

    # (Optional) keep response minimal: answer + plan expiry only
    return json_ok(
        answer=answer,
        plan_expiry=expires_at,
        acct_key=acct_key,
        provider=provider,
        provider_user_id=provider_user_id,
        mode=mode,
        lang=lang,
    )
