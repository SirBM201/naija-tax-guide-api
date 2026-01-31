# app/routes/ask_routes.py
import os
import time
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase

# ✅ Your AI pipeline (place it in one of these paths)
# Option 1 (recommended): app/services/ai.py  -> contains generate_answer()
# If your file is somewhere else, adjust the import line below.
try:
    from app.services.ai import generate_answer  # type: ignore
except Exception:
    generate_answer = None  # will fallback gracefully

log = logging.getLogger(__name__)
bp = Blueprint("ask", __name__)

# -----------------------------
# ENV / SETTINGS
# -----------------------------
ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY") or "").strip()

ASK_RL_WINDOW_SEC = int(os.getenv("ASK_RL_WINDOW_SEC", "60"))
ASK_RL_MAX_REQ_PER_WINDOW = int(os.getenv("ASK_RL_MAX_REQ_PER_WINDOW", "20"))

# Optional: allow higher admin limit (still rate-limited, just higher)
ASK_RL_ADMIN_MULTIPLIER = int(os.getenv("ASK_RL_ADMIN_MULTIPLIER", "5"))

# In-memory limiter: key -> (window_start_ts, count)
_rl_bucket: Dict[str, Tuple[float, int]] = {}


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


def normalize_digits(s: str) -> str:
    return "".join(c for c in (s or "") if c.isdigit())


def normalize_provider(p: str) -> str:
    v = (p or "").strip().lower()
    if v in ("wa", "whatsapp"):
        return "wa"
    if v in ("tg", "telegram"):
        return "tg"
    if v in ("web",):
        return "web"
    # default
    return "web"


def parse_iso_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        s = str(value)
        # Supabase often returns "2026-01-31T20:14:06+00:00" or "...Z"
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


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
def ensure_account(provider: str, provider_user_id: str) -> str:
    """
    Ensures accounts row exists and returns acct_key = acct:<uuid>.
    accounts columns expected:
      - id (uuid)
      - provider (text)
      - provider_user_id (text)
      - phone_e164 (nullable)
    """
    provider = normalize_provider(provider)
    provider_user_id = (provider_user_id or "").strip()

    if provider not in ("wa", "tg", "web"):
        raise ValueError("provider must be wa|tg|web")
    if not provider_user_id:
        raise ValueError("provider_user_id required")

    # normalize web digits
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


def extract_identity(body: Dict[str, Any]) -> Tuple[str, str]:
    """
    Accepts identity in either:
      A) recommended unified format:
         { "provider": "wa|tg|web", "provider_user_id": "..." }
      B) legacy format:
         { "wa_phone": "234..." } -> provider="wa"
         { "user_key": "234..." } -> provider="wa"
    """
    provider = normalize_provider(body.get("provider") or "")
    provider_user_id = (body.get("provider_user_id") or "").strip()

    if provider_user_id:
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


# -----------------------------
# Subscription guard (airtight)
# -----------------------------
def get_subscription_status(acct_key: str) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
    """
    user_subscriptions convention:
      - wa_phone = acct_key ("acct:<uuid>")
      - status (text): "active" / ...
      - plan (text)
      - expires_at (timestamptz)
      - paystack_reference (text) optional

    Returns: (status, plan, expires_at_str, reference)
    """
    r = (
        supabase()
        .table("user_subscriptions")
        .select("status,plan,expires_at,paystack_reference,reference")
        .eq("wa_phone", acct_key)
        .limit(1)
        .execute()
    )

    rows = getattr(r, "data", None) or []
    if not rows:
        return "none", None, None, None

    row = rows[0]
    status = (row.get("status") or "").strip().lower() or "none"
    plan = row.get("plan")
    expires_at = row.get("expires_at")
    reference = row.get("paystack_reference") or row.get("reference")

    # expiry truth ALWAYS wins (safer)
    exp_dt = parse_iso_dt(expires_at)
    if not exp_dt:
        # no/invalid expiry => treat as expired unless status is not active anyway
        if status == "active":
            return "expired", plan, str(expires_at) if expires_at else None, reference
        return status, plan, str(expires_at) if expires_at else None, reference

    if exp_dt <= now_utc():
        return "expired", plan, str(expires_at), reference

    # expiry is in future, but status must still be active
    if status != "active":
        return status, plan, str(expires_at), reference

    return "active", plan, str(expires_at), reference


# -----------------------------
# Rate limiting (clean + safe)
# -----------------------------
def client_ip() -> str:
    return (request.headers.get("x-forwarded-for") or request.remote_addr or "unknown").split(",")[0].strip()


def rate_limit_key(acct_key: str) -> str:
    return acct_key or f"ip:{client_ip()}"


def check_rate_limit(key: str, limit: int) -> Optional[str]:
    """
    Returns None if allowed, else error message.
    """
    now = time.time()
    win_start, count = _rl_bucket.get(key, (now, 0))

    if now - win_start >= ASK_RL_WINDOW_SEC:
        win_start, count = now, 0

    count += 1
    _rl_bucket[key] = (win_start, count)

    if count > limit:
        return "Too many requests. Please wait a bit and try again."
    return None


# -----------------------------
# AI runner (wired to your pipeline)
# -----------------------------
def run_ai_answer(question: str, lang: str = "en") -> str:
    """
    Calls your OpenAI pipeline generate_answer(question, lang).
    Must return a string answer (never None).
    """
    if generate_answer is None:
        return "AI is not configured yet. Please try again later."

    try:
        ans = generate_answer(question=question, lang=lang)
        if ans:
            return str(ans).strip()
        return "Sorry, I couldn't process that right now. Please try again."
    except Exception:
        log.exception("generate_answer failed")
        return "Sorry — system error. Please try again in a moment."


# -----------------------------
# POST /ask
# -----------------------------
@bp.post("/ask")
def ask():
    body = request.get_json(silent=True) or {}

    question = (body.get("question") or body.get("q") or "").strip()
    if not question or len(question) < 2:
        return json_error("Question is required.", 400)

    lang = (body.get("lang") or "en").strip().lower()
    mode = (body.get("mode") or "text").strip().lower()  # kept for compatibility (text/voice), but we return text

    # 1) Identity -> acct_key
    provider, provider_user_id = extract_identity(body)
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

    # 3) Subscription guard (airtight)
    plan = None
    expires_at = None
    reference = None
    status = "none"

    if not admin_ok:
        status, plan, expires_at, reference = get_subscription_status(acct_key)
        if status != "active":
            # IMPORTANT: subscribe_url should point to frontend pricing page
            return json_error(
                "Subscription required or expired.",
                403,
                status=status,
                plan=plan,
                expires_at=expires_at,
                plan_expiry=expires_at,      # legacy
                subscribe_url="/pricing",
                reference=reference,
            )
    else:
        # For admin requests, still useful to expose status info if available
        try:
            status, plan, expires_at, reference = get_subscription_status(acct_key)
        except Exception:
            status, plan, expires_at, reference = "unknown", None, None, None

    # 4) Rate limiting
    limit = ASK_RL_MAX_REQ_PER_WINDOW * (ASK_RL_ADMIN_MULTIPLIER if admin_ok else 1)
    rl_key = rate_limit_key(acct_key)
    msg = check_rate_limit(rl_key, limit=limit)
    if msg:
        return json_error(msg, 429)

    # 5) Run AI
    answer = run_ai_answer(question=question, lang=lang)

    # 6) Response (kept compatible with older clients)
    return json_ok(
        answer=answer,
        audio_url=None,
        provider=provider,
        provider_user_id=provider_user_id,
        acct_key=acct_key,
        subscription_status=status,
        plan=plan,
        expires_at=expires_at,
        plan_expiry=expires_at,  # legacy field some clients expect
        reference=reference,
        mode=mode,
        lang=lang,
        admin=admin_ok,
    )
