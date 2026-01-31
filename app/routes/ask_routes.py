# app/routes/ask_routes.py
import os
import time
import logging
from datetime import datetime, timezone, timedelta, date
from typing import Dict, Optional, Tuple

from flask import Blueprint, request, jsonify
from app.core.supabase_client import supabase
from app.ai.generate_answer import generate_answer

bp = Blueprint("ask", __name__)
log = logging.getLogger(__name__)

# -------------------------------------------------
# CONFIG
# -------------------------------------------------
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()
GRACE_DAYS = int(os.getenv("SUBSCRIPTION_GRACE_DAYS", "3"))

ASK_RL_WINDOW_SEC = int(os.getenv("ASK_RL_WINDOW_SEC", "60"))
ASK_RL_MAX_REQ_PER_WINDOW = int(os.getenv("ASK_RL_MAX_REQ_PER_WINDOW", "20"))

PLAN_LIMITS = {
    "monthly": 50,
    "quarterly": 80,
    "yearly": 150,
}

# in-memory rate limit (defense layer)
_rl_bucket: Dict[str, Tuple[float, int]] = {}

# -------------------------------------------------
# UTILS
# -------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def json_error(msg, status=400, **extra):
    payload = {"ok": False, "message": msg}
    payload.update(extra)
    return jsonify(payload), status

def json_ok(**data):
    payload = {"ok": True}
    payload.update(data)
    return jsonify(payload), 200

def normalize_digits(s: str) -> str:
    return "".join(c for c in (s or "") if c.isdigit())

# -------------------------------------------------
# ADMIN
# -------------------------------------------------
def is_admin() -> bool:
    if not ADMIN_API_KEY:
        return False

    if request.headers.get("x-admin-key") == ADMIN_API_KEY:
        return True

    auth = request.headers.get("Authorization", "")
    return auth == f"Bearer {ADMIN_API_KEY}"

# -------------------------------------------------
# IDENTITY
# -------------------------------------------------
def extract_identity() -> Tuple[str, str]:
    body = request.get_json(silent=True) or {}

    if body.get("provider") and body.get("provider_user_id"):
        p = body["provider"].lower()
        u = body["provider_user_id"]
        return p, normalize_digits(u) if p == "web" else str(u)

    if body.get("wa_phone"):
        return "wa", normalize_digits(body["wa_phone"])

    if body.get("user_key"):
        return "wa", normalize_digits(body["user_key"])

    return "", ""

def ensure_account(provider: str, provider_user_id: str) -> str:
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
        .insert({"provider": provider, "provider_user_id": provider_user_id})
        .execute()
    )
    return f"acct:{ins.data[0]['id']}"

# -------------------------------------------------
# SUBSCRIPTION GUARD
# -------------------------------------------------
def subscription_check(acct_key: str) -> Tuple[bool, Dict]:
    r = (
        supabase()
        .table("user_subscriptions")
        .select("status,plan,expires_at")
        .eq("wa_phone", acct_key)
        .limit(1)
        .execute()
    )

    if not r.data:
        return False, {"status": "none"}

    row = r.data[0]
    plan = row.get("plan")
    expires_at = row.get("expires_at")

    if not expires_at:
        return False, {"status": "expired"}

    exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    now = now_utc()

    if exp >= now:
        return True, {"plan": plan, "expires_at": expires_at}

    if exp + timedelta(days=GRACE_DAYS) >= now:
        return True, {"plan": plan, "grace": True, "expires_at": expires_at}

    return False, {"status": "expired", "plan": plan, "expires_at": expires_at}

# -------------------------------------------------
# DAILY USAGE LIMIT
# -------------------------------------------------
def check_and_increment_usage(acct_key: str, plan: str) -> Optional[str]:
    limit = PLAN_LIMITS.get(plan, 0)
    today = date.today().isoformat()

    r = (
        supabase()
        .table("usage_daily")
        .select("count")
        .eq("acct_key", acct_key)
        .eq("day", today)
        .limit(1)
        .execute()
    )

    count = r.data[0]["count"] if r.data else 0
    if count >= limit:
        return f"Daily limit reached ({limit}). Try again tomorrow."

    if r.data:
        supabase().table("usage_daily").update(
            {"count": count + 1}
        ).eq("acct_key", acct_key).eq("day", today).execute()
    else:
        supabase().table("usage_daily").insert(
            {"acct_key": acct_key, "day": today, "count": 1}
        ).execute()

    return None

# -------------------------------------------------
# RATE LIMIT (SECONDARY)
# -------------------------------------------------
def rate_limit(key: str) -> Optional[str]:
    now = time.time()
    win, cnt = _rl_bucket.get(key, (now, 0))
    if now - win > ASK_RL_WINDOW_SEC:
        win, cnt = now, 0
    cnt += 1
    _rl_bucket[key] = (win, cnt)
    if cnt > ASK_RL_MAX_REQ_PER_WINDOW:
        return "Too many requests. Please slow down."
    return None

# -------------------------------------------------
# ASK ENDPOINT
# -------------------------------------------------
@bp.post("/ask")
def ask():
    body = request.get_json(silent=True) or {}
    question = (body.get("question") or "").strip()
    lang = body.get("lang", "en")

    if len(question) < 2:
        return json_error("Question required")

    provider, provider_user_id = extract_identity()
    if not provider or not provider_user_id:
        return json_error("Identity required")

    acct_key = ensure_account(provider, provider_user_id)

    admin = is_admin()

    # subscription
    if not admin:
        ok, info = subscription_check(acct_key)
        if not ok:
            return json_error(
                "Subscription required",
                403,
                **info,
                subscribe_url="/pricing",
            )

        plan = info.get("plan")
        limit_err = check_and_increment_usage(acct_key, plan)
        if limit_err:
            return json_error(limit_err, 429)

    # rate limit (extra safety)
    rl = rate_limit(acct_key)
    if rl:
        return json_error(rl, 429)

    # AI
    answer = generate_answer(question, lang)
    if not answer:
        return json_error("AI unavailable", 503)

    return json_ok(
        answer=answer,
        provider=provider,
        provider_user_id=provider_user_id,
        acct_key=acct_key,
    )
