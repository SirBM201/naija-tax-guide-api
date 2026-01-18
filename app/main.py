# app/main.py
import os
import json
import hmac
import hashlib
import logging
import uuid
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Dict, Tuple, List

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client

# ------------------------------------------------------------
# App
# ------------------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ------------------------------------------------------------
# ENV
# ------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()

# Paystack
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY).strip()
PAYSTACK_CALLBACK_URL = os.getenv("PAYSTACK_CALLBACK_URL", "").strip()

# WhatsApp Cloud API
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "").strip()
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "").strip()
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()
WHATSAPP_BUSINESS_ACCOUNT_ID = os.getenv("WHATSAPP_BUSINESS_ACCOUNT_ID", "").strip()  # optional

# AI (optional)
AI_ENABLED = os.getenv("AI_ENABLED", "false").strip().lower() in ("1", "true", "yes", "on")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()  # choose your model
OPENAI_TIMEOUT = int(os.getenv("OPENAI_TIMEOUT", "25").strip())

# Credits / quota
# Subscribers: 300 credits per month of plan duration.
CREDITS_PER_MONTH = int(os.getenv("CREDITS_PER_MONTH", "300").strip())

# Free tier (marketing + cost control)
# Total responses/day (library/cache/ai all count). AI is also capped daily.
FREE_DAILY_TOTAL = int(os.getenv("FREE_DAILY_TOTAL", "10").strip())
FREE_DAILY_AI = int(os.getenv("FREE_DAILY_AI", "1").strip())

# OTP / session
OTP_TTL_MINUTES = int(os.getenv("OTP_TTL_MINUTES", "10").strip())
OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", "5").strip())
WEB_SESSION_TTL_DAYS = int(os.getenv("WEB_SESSION_TTL_DAYS", "30").strip())
SESSION_SIGNING_SECRET = os.getenv("SESSION_SIGNING_SECRET", "").strip()  # REQUIRED for web sessions

# CORS
CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:3000").strip()
allowed_origins = [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]

CORS(
    app,
    resources={r"/*": {"origins": allowed_origins}},
    supports_credentials=False,
    allow_headers=["Content-Type", "Authorization", "x-admin-key"],
    methods=["GET", "POST", "OPTIONS"],
)

# ------------------------------------------------------------
# Supabase client
# ------------------------------------------------------------
if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    logging.warning("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing. DB calls will fail.")
supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# ------------------------------------------------------------
# Plans (Payment amounts)
# ------------------------------------------------------------
PLAN_RULES = {
    "monthly":   {"amount_kobo": 3000 * 100,  "days": 30,  "currency": "NGN"},
    "quarterly": {"amount_kobo": 8000 * 100,  "days": 90,  "currency": "NGN"},
    "yearly":    {"amount_kobo": 30000 * 100, "days": 365, "currency": "NGN"},
}

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def require_admin(req) -> Optional[Any]:
    key = req.headers.get("x-admin-key", "")
    if not ADMIN_API_KEY or key != ADMIN_API_KEY:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return None

def normalize_phone(raw: str) -> str:
    s = (raw or "").strip()
    s = s.replace(" ", "").replace("+", "")
    # keep digits only
    s = "".join([c for c in s if c.isdigit()])
    return s

def normalize_question(q: str) -> str:
    s = (q or "").strip().lower()
    s = " ".join(s.split())
    return s

def hmac_hex(secret: str, msg: str) -> str:
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()

# ------------------------------------------------------------
# Subscription + Credits
# ------------------------------------------------------------
def get_subscription_status(wa_phone: str) -> Dict[str, Any]:
    wa_phone = normalize_phone(wa_phone)
    try:
        res = (
            supabase.table("user_subscriptions")
            .select("wa_phone,plan,status,expires_at,updated_at")
            .eq("wa_phone", wa_phone)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return {"exists": False, "active": False, "plan": None, "status": "none", "expires_at": None}

        row = rows[0]
        expires_at = row.get("expires_at")
        status = (row.get("status") or "none").lower()
        plan = (row.get("plan") or "").lower() or None

        active = False
        if status == "active" and expires_at:
            try:
                exp = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
                active = exp > now_utc()
            except Exception:
                # if parsing fails but status says active, treat as active
                active = True

        return {"exists": True, "active": active, "plan": plan, "status": status, "expires_at": expires_at}
    except Exception as e:
        logging.exception("get_subscription_status failed")
        return {"exists": False, "active": False, "plan": None, "status": "error", "expires_at": None, "error": str(e)[:200]}

def activate_user_subscription(wa_phone: str, plan: str) -> None:
    plan = (plan or "").lower().strip()
    days = PLAN_RULES.get(plan, {}).get("days", 30)
    expires_at = iso(now_utc() + timedelta(days=days))
    supabase.table("user_subscriptions").upsert({
        "wa_phone": normalize_phone(wa_phone),
        "plan": plan,
        "status": "active",
        "expires_at": expires_at,
        "updated_at": iso(now_utc())
    }, on_conflict="wa_phone").execute()

def upsert_pending_subscription(wa_phone: str, plan: str) -> None:
    plan = (plan or "").lower().strip()
    supabase.table("user_subscriptions").upsert({
        "wa_phone": normalize_phone(wa_phone),
        "plan": plan,
        "status": "pending",
        "expires_at": None,
        "updated_at": iso(now_utc())
    }, on_conflict="wa_phone").execute()

def _plan_total_credits(plan: str) -> int:
    plan = (plan or "").lower().strip()
    if plan not in PLAN_RULES:
        return 0
    days = int(PLAN_RULES[plan]["days"])
    months = max(1, int(round(days / 30.0)))
    return months * CREDITS_PER_MONTH  # monthly=300, quarterly=900, yearly=3600

def _subscription_bucket_key(wa_phone: str, plan: str, expires_at: str) -> str:
    # A stable key for the duration of a subscription instance
    # If expires_at changes (renewal), key changes naturally.
    return f"sub:{normalize_phone(wa_phone)}:{(plan or '').lower()}:{str(expires_at)}"

def _free_bucket_key(wa_phone: str, day_utc: str) -> str:
    # daily bucket for free users
    return f"free:{normalize_phone(wa_phone)}:{day_utc}"

def _get_topup_credits(wa_phone: str) -> int:
    # sum successful topups for this phone
    try:
        res = (
            supabase.table("credit_topups")
            .select("credits,status")
            .eq("wa_phone", normalize_phone(wa_phone))
            .execute()
        )
        total = 0
        for r in (res.data or []):
            if (r.get("status") or "").lower() == "success":
                total += int(r.get("credits") or 0)
        return total
    except Exception:
        return 0

def _get_usage_row(bucket_key: str) -> Dict[str, Any]:
    try:
        res = (
            supabase.table("usage_counters")
            .select("bucket_key,wa_phone,used_total,used_ai,updated_at")
            .eq("bucket_key", bucket_key)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if rows:
            return rows[0]
        return {"bucket_key": bucket_key, "used_total": 0, "used_ai": 0}
    except Exception:
        return {"bucket_key": bucket_key, "used_total": 0, "used_ai": 0}

def _upsert_usage(bucket_key: str, wa_phone: str, used_total: int, used_ai: int) -> None:
    supabase.table("usage_counters").upsert({
        "bucket_key": bucket_key,
        "wa_phone": normalize_phone(wa_phone),
        "used_total": int(used_total),
        "used_ai": int(used_ai),
        "updated_at": iso(now_utc()),
    }, on_conflict="bucket_key").execute()

def get_credit_state(wa_phone: str) -> Dict[str, Any]:
    """
    Returns:
      - mode: "sub" or "free"
      - bucket_key
      - total_credits (base + topup if sub, else FREE_DAILY_TOTAL)
      - ai_cap (if free: FREE_DAILY_AI, if sub: None)
      - used_total, used_ai
      - remaining_total, remaining_ai (if free)
      - plan info if sub
    """
    wa_phone = normalize_phone(wa_phone)
    sub = get_subscription_status(wa_phone)

    if sub.get("active") and sub.get("plan") and sub.get("expires_at"):
        plan = sub["plan"]
        expires_at = sub["expires_at"]
        base = _plan_total_credits(plan)
        topups = _get_topup_credits(wa_phone)
        total = base + topups

        bucket_key = _subscription_bucket_key(wa_phone, plan, expires_at)
        usage = _get_usage_row(bucket_key)

        used_total = int(usage.get("used_total") or 0)
        used_ai = int(usage.get("used_ai") or 0)

        remaining_total = max(0, total - used_total)
        return {
            "mode": "sub",
            "plan": plan,
            "expires_at": expires_at,
            "bucket_key": bucket_key,
            "base_credits": base,
            "topup_credits": topups,
            "total_credits": total,
            "used_total": used_total,
            "used_ai": used_ai,
            "remaining_total": remaining_total,
        }

    # Free daily bucket
    day_utc = now_utc().date().isoformat()
    bucket_key = _free_bucket_key(wa_phone, day_utc)
    usage = _get_usage_row(bucket_key)
    used_total = int(usage.get("used_total") or 0)
    used_ai = int(usage.get("used_ai") or 0)

    remaining_total = max(0, FREE_DAILY_TOTAL - used_total)
    remaining_ai = max(0, FREE_DAILY_AI - used_ai)

    return {
        "mode": "free",
        "day_utc": day_utc,
        "bucket_key": bucket_key,
        "total_credits": FREE_DAILY_TOTAL,
        "ai_cap": FREE_DAILY_AI,
        "used_total": used_total,
        "used_ai": used_ai,
        "remaining_total": remaining_total,
        "remaining_ai": remaining_ai,
    }

def consume_credit(wa_phone: str, is_ai: bool) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Consumes 1 credit for any response (library/cache/ai).
    If is_ai=True, also counts against AI cap for free users.
    """
    state = get_credit_state(wa_phone)

    if state["remaining_total"] <= 0:
        if state["mode"] == "sub":
            return False, "Credits finished. Reply TOPUP to buy more credits.", state
        return False, "Daily limit reached. Please try tomorrow or subscribe.", state

    if is_ai and state["mode"] == "free":
        if state.get("remaining_ai", 0) <= 0:
            return False, "Free AI quota reached for today. Try again tomorrow or subscribe.", state

    # Apply update
    bucket_key = state["bucket_key"]
    used_total = int(state.get("used_total") or 0) + 1
    used_ai = int(state.get("used_ai") or 0) + (1 if is_ai else 0)
    try:
        _upsert_usage(bucket_key, wa_phone, used_total, used_ai)
    except Exception:
        # If DB write fails, do not block user hard; but log
        logging.exception("consume_credit failed to persist usage")

    # Return updated state snapshot (best effort)
    state["used_total"] = used_total
    state["used_ai"] = used_ai
    state["remaining_total"] = max(0, int(state["total_credits"]) - used_total) if state["mode"] == "sub" else max(0, FREE_DAILY_TOTAL - used_total)
    if state["mode"] == "free":
        state["remaining_ai"] = max(0, FREE_DAILY_AI - used_ai)

    return True, "ok", state

# ------------------------------------------------------------
# QA Library + QA Cache
# ------------------------------------------------------------
def qa_library_get(question: str) -> Optional[str]:
    nq = normalize_question(question)
    if not nq:
        return None
    try:
        # expects: normalized_question, answer, enabled(bool), priority(int)
        res = (
            supabase.table("qa_library")
            .select("id,answer,priority")
            .eq("normalized_question", nq)
            .eq("enabled", True)
            .order("priority", desc=True)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return None
        ans = rows[0].get("answer")
        return ans
    except Exception:
        logging.exception("qa_library_get failed")
        return None

def cache_get(question: str) -> Optional[str]:
    nq = normalize_question(question)
    if not nq:
        return None
    try:
        res = (
            supabase.table("qa_cache")
            .select("id,answer,use_count")
            .eq("normalized_question", nq)
            .order("last_used_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return None

        row = rows[0]
        ans = row.get("answer")

        # increment use_count + update last_used_at (best effort)
        try:
            cid = row.get("id")
            use_count = int(row.get("use_count") or 0) + 1
            if cid:
                supabase.table("qa_cache").update({
                    "use_count": use_count,
                    "last_used_at": iso(now_utc())
                }).eq("id", cid).execute()
        except Exception:
            pass

        return ans
    except Exception:
        logging.exception("cache_get failed")
        return None

def cache_set(question: str, answer: str) -> None:
    nq = normalize_question(question)
    if not nq or not (answer or "").strip():
        return
    try:
        supabase.table("qa_cache").insert({
            "normalized_question": nq,
            "answer": (answer or "").strip(),
            "tags": [],
            "use_count": 0,
            "last_used_at": iso(now_utc()),
            "created_at": iso(now_utc()),
        }).execute()
    except Exception:
        return

# ------------------------------------------------------------
# AI (OpenAI)
# ------------------------------------------------------------
def ai_answer(question: str) -> str:
    # If AI disabled or no key, return a safe fallback
    if not AI_ENABLED or not OPENAI_API_KEY:
        return (
            "I can help, but AI is currently unavailable.\n"
            "Please try again later or ask a simpler tax question.\n"
            "Tip: Use PLANS to subscribe for full support."
        )

    # Minimal, low-cost prompt
    system = (
        "You are Naija Tax Guide. Answer Nigerian tax questions clearly and simply. "
        "Use short paragraphs, practical steps, and avoid legal overpromising. "
        "If unsure, say what to confirm with FIRS or the state tax authority."
    )

    payload = {
        "model": OPENAI_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": question}
        ],
        "temperature": 0.2,
        "max_tokens": 350,
    }

    try:
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
            json=payload,
            timeout=OPENAI_TIMEOUT,
        )
        if r.status_code >= 300:
            logging.warning(f"OpenAI error {r.status_code}: {r.text[:300]}")
            return "Sorry — AI is temporarily busy. Please try again in a moment."

        data = r.json()
        text = (((data.get("choices") or [])[0].get("message") or {}).get("content") or "").strip()
        return text or "Sorry — I could not generate a response. Please rephrase your question."
    except Exception:
        logging.exception("ai_answer failed")
        return "Sorry — AI failed. Please try again shortly."

# ------------------------------------------------------------
# WhatsApp Cloud API helpers
# ------------------------------------------------------------
def wa_api_url(path: str) -> str:
    return f"https://graph.facebook.com/v24.0{path}"

def send_whatsapp_text(to_wa_phone: str, text: str) -> Tuple[bool, str]:
    if not WHATSAPP_TOKEN or not WHATSAPP_PHONE_NUMBER_ID:
        return False, "WHATSAPP_TOKEN or WHATSAPP_PHONE_NUMBER_ID missing"

    to_wa_phone = normalize_phone(to_wa_phone)
    url = wa_api_url(f"/{WHATSAPP_PHONE_NUMBER_ID}/messages")
    headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}", "Content-Type": "application/json"}

    payload = {
        "messaging_product": "whatsapp",
        "to": to_wa_phone,
        "type": "text",
        "text": {"body": (text or "")[:3800]},
    }

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=25)
        if r.status_code >= 300:
            return False, f"WhatsApp send failed: {r.status_code} {r.text[:250]}"
        return True, "ok"
    except Exception as e:
        return False, f"WhatsApp send exception: {str(e)[:200]}"

def format_plans_text() -> str:
    return (
        "Naija Tax Guide Plans:\n"
        "1) MONTHLY - ₦3,000 (300 credits)\n"
        "2) QUARTERLY - ₦8,000 (900 credits)\n"
        "3) YEARLY - ₦30,000 (3,600 credits)\n\n"
        "Reply:\n"
        "SUBSCRIBE monthly\n"
        "SUBSCRIBE quarterly\n"
        "SUBSCRIBE yearly\n\n"
        "Or reply STATUS to check your plan."
    )

def format_help_text() -> str:
    return (
        "Commands you can send:\n"
        "HELP - show this menu\n"
        "PLANS - see subscription plans\n"
        "SUBSCRIBE monthly|quarterly|yearly - start a plan\n"
        "STATUS - check plan + remaining credits\n"
        "TOPUP - buy extra credits (optional)\n\n"
        "Or send any tax question directly."
    )

def format_status_text(wa_phone: str) -> str:
    sub = get_subscription_status(wa_phone)
    state = get_credit_state(wa_phone)

    if sub.get("status") == "error":
        return "STATUS: Unable to read subscription right now. Please try again."

    if not sub.get("exists") or not sub.get("active"):
        return (
            "STATUS: No active subscription.\n"
            f"Daily free credits: {FREE_DAILY_TOTAL}\n"
            f"Used today: {state.get('used_total', 0)}\n"
            f"Remaining today: {state.get('remaining_total', 0)}\n\n"
            "Reply PLANS to subscribe."
        )

    plan = (sub.get("plan") or "unknown").upper()
    expires_at = sub.get("expires_at") or "-"
    base = state.get("base_credits", 0)
    top = state.get("topup_credits", 0)
    used = state.get("used_total", 0)
    rem = state.get("remaining_total", 0)
    return (
        "STATUS:\n"
        f"Plan: {plan}\n"
        f"Expires: {expires_at}\n"
        f"Credits: {base} + Topup {top} = {base + top}\n"
        f"Used: {used}\n"
        f"Remaining: {rem}\n"
    )

def handle_inbound_command(from_phone: str, text: str) -> Optional[str]:
    t = (text or "").strip()
    if not t:
        return None

    upper = t.upper()

    if upper == "HELP":
        return format_help_text()

    if upper == "PLANS":
        return format_plans_text()

    if upper == "STATUS":
        return format_status_text(from_phone)

    if upper.startswith("SUBSCRIBE"):
        parts = t.split()
        if len(parts) < 2:
            return "Usage: SUBSCRIBE monthly|quarterly|yearly\nReply PLANS to see pricing."
        plan = parts[1].strip().lower()
        if plan not in PLAN_RULES:
            return "Invalid plan. Use: monthly, quarterly, yearly."

        try:
            upsert_pending_subscription(from_phone, plan)
        except Exception:
            pass

        return (
            f"SUBSCRIBE: {plan.upper()} selected.\n"
            "Next step: complete payment on the website.\n"
            "If you already paid, reply STATUS in 1–2 minutes."
        )

    if upper == "TOPUP":
        return (
            "TOPUP is available.\n"
            "Please use the website topup page to buy extra credits.\n"
            "If you need help, reply HELP."
        )

    return None

# ------------------------------------------------------------
# OTP + Web Sessions
# ------------------------------------------------------------
def _otp_hash(code: str) -> str:
    # Hash OTP so we don't store plaintext
    return hashlib.sha256(code.encode("utf-8")).hexdigest()

def create_session_token(wa_phone: str) -> str:
    if not SESSION_SIGNING_SECRET:
        # Force correct setup (otherwise tokens are forgeable)
        raise RuntimeError("SESSION_SIGNING_SECRET not set")
    rid = uuid.uuid4().hex
    base = f"{rid}.{normalize_phone(wa_phone)}"
    sig = hmac_hex(SESSION_SIGNING_SECRET, base)
    return f"{base}.{sig}"

def verify_session_token(token: str) -> Optional[str]:
    if not token or not SESSION_SIGNING_SECRET:
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    rid, phone, sig = parts
    base = f"{rid}.{phone}"
    expected = hmac_hex(SESSION_SIGNING_SECRET, base)
    if not hmac.compare_digest(expected, sig):
        return None

    # Validate against DB session store
    try:
        res = (
            supabase.table("web_sessions")
            .select("token,wa_phone,expires_at")
            .eq("token", token)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return None
        exp = rows[0].get("expires_at")
        if exp:
            exp_dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
            if exp_dt <= now_utc():
                return None
        return normalize_phone(rows[0].get("wa_phone") or "")
    except Exception:
        return None

@app.post("/auth/request_otp")
def auth_request_otp():
    body = request.get_json(silent=True) or {}
    wa_phone = normalize_phone(body.get("wa_phone") or "")
    if not wa_phone:
        return jsonify({"ok": False, "error": "wa_phone is required"}), 400

    # Generate 6-digit OTP
    code = f"{secrets.randbelow(1000000):06d}"
    code_hash = _otp_hash(code)
    expires_at = iso(now_utc() + timedelta(minutes=OTP_TTL_MINUTES))

    try:
        # store/update otp_codes (one active per phone)
        supabase.table("otp_codes").upsert({
            "wa_phone": wa_phone,
            "code_hash": code_hash,
            "expires_at": expires_at,
            "attempts": 0,
            "created_at": iso(now_utc()),
        }, on_conflict="wa_phone").execute()
    except Exception as e:
        logging.exception("otp upsert failed")
        return jsonify({"ok": False, "error": f"db_error: {str(e)[:200]}"}), 500

    msg = f"Your Naija Tax Guide login code is: {code}\nExpires in {OTP_TTL_MINUTES} minutes."
    ok, info = send_whatsapp_text(wa_phone, msg)
    if not ok:
        return jsonify({"ok": False, "error": info}), 502

    return jsonify({"ok": True})

@app.post("/auth/verify_otp")
def auth_verify_otp():
    body = request.get_json(silent=True) or {}
    wa_phone = normalize_phone(body.get("wa_phone") or "")
    code = (body.get("code") or "").strip()

    if not wa_phone or not code:
        return jsonify({"ok": False, "error": "wa_phone and code are required"}), 400

    try:
        res = (
            supabase.table("otp_codes")
            .select("wa_phone,code_hash,expires_at,attempts")
            .eq("wa_phone", wa_phone)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return jsonify({"ok": False, "error": "OTP not found. Request a new code."}), 400

        row = rows[0]
        attempts = int(row.get("attempts") or 0)
        if attempts >= OTP_MAX_ATTEMPTS:
            return jsonify({"ok": False, "error": "Too many attempts. Request a new code."}), 400

        exp = row.get("expires_at")
        if exp:
            exp_dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
            if exp_dt <= now_utc():
                return jsonify({"ok": False, "error": "OTP expired. Request a new code."}), 400

        if _otp_hash(code) != (row.get("code_hash") or ""):
            # increment attempts
            supabase.table("otp_codes").update({
                "attempts": attempts + 1
            }).eq("wa_phone", wa_phone).execute()
            return jsonify({"ok": False, "error": "Invalid code."}), 400

        # Valid OTP -> create session
        token = create_session_token(wa_phone)
        sess_exp = iso(now_utc() + timedelta(days=WEB_SESSION_TTL_DAYS))
        supabase.table("web_sessions").insert({
            "token": token,
            "wa_phone": wa_phone,
            "expires_at": sess_exp,
            "created_at": iso(now_utc()),
        }).execute()

        # optional: delete otp row (one-time)
        try:
            supabase.table("otp_codes").delete().eq("wa_phone", wa_phone).execute()
        except Exception:
            pass

        return jsonify({"ok": True, "token": token, "expires_at": sess_exp})
    except RuntimeError as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    except Exception as e:
        logging.exception("verify_otp failed")
        return jsonify({"ok": False, "error": f"server_error: {str(e)[:200]}"}), 500

# ------------------------------------------------------------
# Health / Debug
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({
        "ok": True,
        "service": "naija-tax-guide",
        "time_utc": now_utc().isoformat(),
        "ai_enabled": AI_ENABLED,
    })

@app.get("/routes")
def routes():
    out = []
    for rule in app.url_map.iter_rules():
        out.append({
            "endpoint": rule.endpoint,
            "methods": sorted([m for m in rule.methods if m in ("GET", "POST", "OPTIONS")]),
            "rule": str(rule),
        })
    return jsonify(sorted(out, key=lambda x: x["rule"]))

# ------------------------------------------------------------
# Core Answering Logic (Library -> Cache -> AI) with Credits
# ------------------------------------------------------------
def answer_with_credits(wa_phone: str, question: str) -> Dict[str, Any]:
    """
    Enforces credits for any response:
      - qa_library hit consumes 1 credit
      - qa_cache hit consumes 1 credit
      - AI consumes 1 credit (and counts against free AI cap)
    """
    wa_phone = normalize_phone(wa_phone)
    q = (question or "").strip()
    if not wa_phone:
        return {"ok": False, "error": "wa_phone is required"}, 400
    if not q:
        return {"ok": False, "error": "question is required"}, 400

    # 1) Library
    lib = qa_library_get(q)
    if lib:
        okc, msg, state = consume_credit(wa_phone, is_ai=False)
        if not okc:
            return {"ok": False, "error": msg, "meta": {"credits": state}}, 429
        return {"ok": True, "answer": lib, "meta": {"source": "qa_library", "credits": state}}

    # 2) Cache
    cached = cache_get(q)
    if cached:
        okc, msg, state = consume_credit(wa_phone, is_ai=False)
        if not okc:
            return {"ok": False, "error": msg, "meta": {"credits": state}}, 429
        return {"ok": True, "answer": cached, "meta": {"source": "qa_cache", "credits": state}}

    # 3) AI
    okc, msg, state = consume_credit(wa_phone, is_ai=True)
    if not okc:
        return {"ok": False, "error": msg, "meta": {"credits": state}}, 429

    ans = ai_answer(q)
    # Save to cache to reduce future cost
    cache_set(q, ans)
    return {"ok": True, "answer": ans, "meta": {"source": "ai", "credits": state}}

# ------------------------------------------------------------
# ASK (Web Chat) - Requires session token (OTP verified)
# ------------------------------------------------------------
@app.post("/ask")
def ask():
    body = request.get_json(silent=True) or {}
    question = (body.get("question") or "").strip()

    # Token may be passed as Authorization Bearer or in body
    auth = request.headers.get("Authorization", "").strip()
    token = ""
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
    if not token:
        token = (body.get("token") or "").strip()

    wa_phone = verify_session_token(token)
    if not wa_phone:
        return jsonify({"ok": False, "error": "Unauthorized. Please login (OTP) again."}), 401

    result = answer_with_credits(wa_phone, question)
    if isinstance(result, tuple):
        payload, status = result
        return jsonify(payload), status
    return jsonify(result)

# ------------------------------------------------------------
# Paystack: Initialize subscription payment
# ------------------------------------------------------------
@app.post("/paystack/initialize")
def paystack_initialize():
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500

    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    wa_phone = normalize_phone(body.get("wa_phone") or "")
    plan = (body.get("plan") or "").strip().lower()

    if not email or "@" not in email:
        return jsonify({"ok": False, "error": "Valid email is required"}), 400
    if not wa_phone:
        return jsonify({"ok": False, "error": "wa_phone is required"}), 400
    if plan not in PLAN_RULES:
        return jsonify({"ok": False, "error": f"Invalid plan. Use {list(PLAN_RULES.keys())}"}), 400

    rule = PLAN_RULES[plan]
    reference = uuid.uuid4().hex[:12]

    amount_kobo = int(rule["amount_kobo"])
    amount = amount_kobo / 100.0

    # 1) Payment row
    try:
        supabase.table("payments").insert({
            "reference": reference,
            "wa_phone": wa_phone,
            "provider": "paystack",
            "plan": plan,
            "amount_kobo": amount_kobo,
            "amount": amount,
            "currency": rule["currency"],
            "status": "pending",
            "created_at": iso(now_utc()),
            "paid_at": None,
            "email": email,
        }).execute()
    except Exception as e:
        logging.exception("Failed inserting payment row")
        return jsonify({"ok": False, "error": f"db_insert_failed: {str(e)[:300]}"}), 500

    # 2) Subscription pending
    try:
        upsert_pending_subscription(wa_phone, plan)
    except Exception:
        pass

    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}", "Content-Type": "application/json"}
    payload = {
        "email": email,
        "amount": amount_kobo,
        "reference": reference,
        "metadata": {"wa_phone": wa_phone, "plan": plan, "type": "subscription"}
    }
    if PAYSTACK_CALLBACK_URL:
        payload["callback_url"] = PAYSTACK_CALLBACK_URL

    r = requests.post("https://api.paystack.co/transaction/initialize", headers=headers, json=payload, timeout=25)

    try:
        data = r.json()
    except Exception:
        supabase.table("payments").update({"status": "failed"}).eq("reference", reference).execute()
        return jsonify({"ok": False, "error": f"Paystack non-JSON response: {r.text[:200]}"}), 502

    if r.status_code >= 300 or not data.get("status"):
        supabase.table("payments").update({"status": "failed"}).eq("reference", reference).execute()
        msg = data.get("message") or f"HTTP {r.status_code}"
        return jsonify({"ok": False, "error": f"Paystack init failed: {msg}"}), 400

    auth_url = (data.get("data") or {}).get("authorization_url")
    return jsonify({"ok": True, "reference": reference, "authorization_url": auth_url})

# ------------------------------------------------------------
# Optional: Paystack Initialize TOPUP Credits
# (If you already implemented topups SQL, this works.
# If not, you can ignore until later.)
# ------------------------------------------------------------
@app.post("/paystack/topup_initialize")
def paystack_topup_initialize():
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500

    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    wa_phone = normalize_phone(body.get("wa_phone") or "")
    credits = int(body.get("credits") or 0)

    # pricing for topup: you can set NGN per credit in env
    NGN_PER_CREDIT = int(os.getenv("NGN_PER_CREDIT", "10").strip())  # example: 10 NGN per credit
    amount_kobo = credits * NGN_PER_CREDIT * 100

    if not email or "@" not in email:
        return jsonify({"ok": False, "error": "Valid email is required"}), 400
    if not wa_phone:
        return jsonify({"ok": False, "error": "wa_phone is required"}), 400
    if credits <= 0:
        return jsonify({"ok": False, "error": "credits must be > 0"}), 400

    reference = "tp_" + uuid.uuid4().hex[:12]

    # store pending topup
    try:
        supabase.table("credit_topups").insert({
            "reference": reference,
            "wa_phone": wa_phone,
            "credits": credits,
            "status": "pending",
            "created_at": iso(now_utc()),
            "paid_at": None,
            "email": email,
        }).execute()
    except Exception as e:
        logging.exception("Failed inserting topup row")
        return jsonify({"ok": False, "error": f"db_insert_failed: {str(e)[:300]}"}), 500

    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}", "Content-Type": "application/json"}
    payload = {
        "email": email,
        "amount": amount_kobo,
        "reference": reference,
        "metadata": {"wa_phone": wa_phone, "credits": credits, "type": "topup"}
    }
    if PAYSTACK_CALLBACK_URL:
        payload["callback_url"] = PAYSTACK_CALLBACK_URL

    r = requests.post("https://api.paystack.co/transaction/initialize", headers=headers, json=payload, timeout=25)

    try:
        data = r.json()
    except Exception:
        supabase.table("credit_topups").update({"status": "failed"}).eq("reference", reference).execute()
        return jsonify({"ok": False, "error": f"Paystack non-JSON response: {r.text[:200]}"}), 502

    if r.status_code >= 300 or not data.get("status"):
        supabase.table("credit_topups").update({"status": "failed"}).eq("reference", reference).execute()
        msg = data.get("message") or f"HTTP {r.status_code}"
        return jsonify({"ok": False, "error": f"Paystack init failed: {msg}"}), 400

    auth_url = (data.get("data") or {}).get("authorization_url")
    return jsonify({"ok": True, "reference": reference, "authorization_url": auth_url})

# ------------------------------------------------------------
# Paystack: Webhook (handles subscription + topup)
# ------------------------------------------------------------
@app.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if not PAYSTACK_WEBHOOK_SECRET:
        return "PAYSTACK_WEBHOOK_SECRET not set", 500

    expected = hmac.new(PAYSTACK_WEBHOOK_SECRET.encode("utf-8"), raw, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return "invalid signature", 401

    try:
        event = json.loads(raw.decode("utf-8"))
    except Exception:
        return "invalid json", 400

    event_type = event.get("event", "")
    data = event.get("data") or {}
    reference = data.get("reference") or ""
    is_success = event_type in ("charge.success", "transaction.success")

    if not reference:
        return "ok", 200

    meta = data.get("metadata") or {}
    typ = (meta.get("type") or "").lower()

    # 1) Subscription payments
    if not typ or typ == "subscription":
        pay_row = supabase.table("payments").select("*").eq("reference", reference).limit(1).execute()
        rows = pay_row.data or []
        if not rows:
            logging.warning(f"Webhook reference not found in payments: {reference}")
            return "ok", 200

        pay = rows[0]
        wa_phone = pay.get("wa_phone")
        plan = pay.get("plan")

        wa_phone = wa_phone or meta.get("wa_phone")
        plan = plan or meta.get("plan")

        if not wa_phone or not plan:
            logging.warning(f"Webhook missing wa_phone/plan for reference={reference}")
            return "ok", 200

        if is_success:
            amount_kobo = int(data.get("amount") or pay.get("amount_kobo") or 0)
            amount = amount_kobo / 100.0

            supabase.table("payments").update({
                "status": "success",
                "paid_at": iso(now_utc()),
                "amount_kobo": amount_kobo,
                "amount": amount,
                "currency": data.get("currency") or pay.get("currency") or "NGN",
            }).eq("reference", reference).execute()

            activate_user_subscription(wa_phone, plan)

        return "ok", 200

    # 2) Topup payments
    if typ == "topup":
        top_row = supabase.table("credit_topups").select("*").eq("reference", reference).limit(1).execute()
        rows = top_row.data or []
        if not rows:
            logging.warning(f"Webhook reference not found in credit_topups: {reference}")
            return "ok", 200

        row = rows[0]
        wa_phone = row.get("wa_phone") or meta.get("wa_phone")
        if not wa_phone:
            return "ok", 200

        if is_success:
            supabase.table("credit_topups").update({
                "status": "success",
                "paid_at": iso(now_utc()),
            }).eq("reference", reference).execute()

        return "ok", 200

    return "ok", 200

# ------------------------------------------------------------
# WhatsApp Webhook (Meta verification + inbound messages)
# ------------------------------------------------------------
@app.get("/whatsapp/webhook")
def whatsapp_webhook_verify():
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    logging.info(f"WA_VERIFY_HIT mode={mode} token_len={len(token)} has_challenge={bool(challenge)}")

    if mode == "subscribe" and token and WHATSAPP_VERIFY_TOKEN and token == WHATSAPP_VERIFY_TOKEN:
        return challenge, 200

    return "forbidden", 403

@app.post("/whatsapp/webhook")
def whatsapp_webhook_inbound():
    payload = request.get_json(silent=True) or {}

    # Log webhook hit
    try:
        field = (((payload.get("entry") or [])[0].get("changes") or [])[0]).get("field")
    except Exception:
        field = None
    logging.info(f"WA_WEBHOOK_HIT field={field} keys={list(payload.keys())}")

    try:
        entry = (payload.get("entry") or [])[0]
        change = (entry.get("changes") or [])[0]
        value = change.get("value") or {}
    except Exception:
        return "ok", 200

    # Inbound messages
    messages = value.get("messages") or []
    if messages:
        msg = messages[0]
        from_phone = normalize_phone(msg.get("from") or "")
        msg_type = msg.get("type") or ""

        text_body = ""
        if msg_type == "text":
            text_body = ((msg.get("text") or {}).get("body") or "").strip()

        logging.info(f"WA_MESSAGE from={from_phone} type={msg_type} body={text_body[:120]}")

        if from_phone and text_body:
            # 1) Commands
            cmd_response = handle_inbound_command(from_phone, text_body)
            if cmd_response:
                ok, info = send_whatsapp_text(from_phone, cmd_response)
                logging.info(f"WA_REPLY_CMD ok={ok} info={info}")
                return "ok", 200

            # 2) Normal question -> library/cache/ai with credits
            try:
                result = answer_with_credits(from_phone, text_body)
                if isinstance(result, tuple):
                    payload, status = result
                    # Convert error into WhatsApp text (friendly)
                    err = payload.get("error") or "Sorry — unable to respond."
                    ok, info = send_whatsapp_text(from_phone, err)
                    logging.info(f"WA_REPLY_ERR ok={ok} info={info} status={status}")
                    return "ok", 200

                ans = result.get("answer") or "Sorry — no answer."
                ok, info = send_whatsapp_text(from_phone, ans)
                logging.info(f"WA_REPLY ok={ok} info={info} source={result.get('meta', {}).get('source')}")
            except Exception:
                logging.exception("Inbound message handling failed")
                send_whatsapp_text(from_phone, "Sorry — system error. Please try again.")

            return "ok", 200

    # Status updates (delivered/read/etc.)
    statuses = value.get("statuses") or []
    if statuses:
        st = statuses[0]
        logging.info(f"WA_STATUS id={st.get('id')} status={st.get('status')} to={st.get('recipient_id')}")

    return "ok", 200

# ------------------------------------------------------------
# Admin endpoints
# ------------------------------------------------------------
@app.get("/admin/subscriptions")
def admin_subscriptions():
    auth = require_admin(request)
    if auth:
        return auth

    res = (
        supabase.table("user_subscriptions")
        .select("wa_phone,plan,status,expires_at,updated_at")
        .order("updated_at", desc=True)
        .execute()
    )
    return jsonify(res.data or [])

@app.get("/admin/payments")
def admin_payments():
    auth = require_admin(request)
    if auth:
        return auth

    res = (
        supabase.table("payments")
        .select("reference,wa_phone,provider,plan,amount,amount_kobo,currency,status,created_at,paid_at")
        .order("created_at", desc=True)
        .execute()
    )
    return jsonify(res.data or [])

@app.get("/admin/usage")
def admin_usage():
    auth = require_admin(request)
    if auth:
        return auth

    res = (
        supabase.table("usage_counters")
        .select("bucket_key,wa_phone,used_total,used_ai,updated_at")
        .order("updated_at", desc=True)
        .limit(200)
        .execute()
    )
    return jsonify(res.data or [])
