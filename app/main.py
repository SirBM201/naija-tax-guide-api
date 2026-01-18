# app/main.py
import os
import json
import hmac
import hashlib
import logging
import uuid
import random
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
AI_ENABLED = os.getenv("AI_ENABLED", "true").strip().lower() in ("1", "true", "yes", "on")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()  # example default

# Usage control
DAILY_TOTAL_LIMIT = int(os.getenv("DAILY_TOTAL_LIMIT", "100").strip())  # applies to ALL requests (cache/library/ai)
FREE_AI_PER_DAY_NON_SUB = int(os.getenv("FREE_AI_PER_DAY_NON_SUB", "1").strip())  # marketing: 1 AI/day for non-subscribers
AI_CREDITS_PER_MONTH = int(os.getenv("AI_CREDITS_PER_MONTH", "300").strip())

# OTP (optional enforcement)
REQUIRE_OTP = os.getenv("REQUIRE_OTP", "false").strip().lower() in ("1", "true", "yes", "on")
OTP_TTL_MINUTES = int(os.getenv("OTP_TTL_MINUTES", "10").strip())
OTP_SENDER = os.getenv("OTP_SENDER", "whatsapp").strip().lower()  # whatsapp now, sms later

# CORS
CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:3000").strip()
allowed_origins = [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]

CORS(
    app,
    resources={r"/*": {"origins": allowed_origins}},
    supports_credentials=False,
    allow_headers=["Content-Type", "x-admin-key", "x-session-token"],
    methods=["GET", "POST", "OPTIONS"],
)

# ------------------------------------------------------------
# Supabase
# ------------------------------------------------------------
if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    logging.warning("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing. DB calls will fail.")
supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# ------------------------------------------------------------
# Plans (time bound)
# ------------------------------------------------------------
PLAN_RULES = {
    "monthly":   {"amount_kobo": 3000 * 100,  "days": 30,  "currency": "NGN", "ai_credits": AI_CREDITS_PER_MONTH},
    "quarterly": {"amount_kobo": 8000 * 100,  "days": 90,  "currency": "NGN", "ai_credits": AI_CREDITS_PER_MONTH * 3},
    "yearly":    {"amount_kobo": 30000 * 100, "days": 365, "currency": "NGN", "ai_credits": AI_CREDITS_PER_MONTH * 12},
}

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def today_key_utc() -> str:
    # YYYY-MM-DD
    return now_utc().strftime("%Y-%m-%d")

def require_admin(req) -> Optional[Any]:
    key = req.headers.get("x-admin-key", "")
    if not ADMIN_API_KEY or key != ADMIN_API_KEY:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return None

def normalize_phone(raw: str) -> str:
    s = (raw or "").strip()
    s = s.replace(" ", "").replace("+", "")
    return s

def normalize_question(q: str) -> str:
    s = (q or "").strip().lower()
    s = " ".join(s.split())
    return s

def safe_int(x, default=0) -> int:
    try:
        return int(x)
    except Exception:
        return default

def parse_iso_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None

# ------------------------------------------------------------
# Subscriptions (table: user_subscriptions)
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
        plan = row.get("plan") or None

        active = False
        exp = parse_iso_dt(expires_at)
        if status == "active" and exp:
            active = exp > now_utc()
        elif status == "active" and not exp:
            active = True

        return {"exists": True, "active": active, "plan": plan, "status": status, "expires_at": expires_at}
    except Exception as e:
        logging.exception("get_subscription_status failed")
        return {"exists": False, "active": False, "plan": None, "status": "error", "expires_at": None, "error": str(e)[:200]}

def activate_user_subscription(wa_phone: str, plan: str) -> None:
    plan = (plan or "").strip().lower()
    rule = PLAN_RULES.get(plan) or PLAN_RULES["monthly"]
    days = int(rule["days"])
    expires_at = iso(now_utc() + timedelta(days=days))

    # update subscription
    supabase.table("user_subscriptions").upsert({
        "wa_phone": normalize_phone(wa_phone),
        "plan": plan,
        "status": "active",
        "expires_at": expires_at,
        "updated_at": iso(now_utc())
    }, on_conflict="wa_phone").execute()

    # allocate credits with rollover until plan expiry
    allocate_subscription_credits(wa_phone, plan, expires_at)

def upsert_pending_subscription(wa_phone: str, plan: str) -> None:
    supabase.table("user_subscriptions").upsert({
        "wa_phone": normalize_phone(wa_phone),
        "plan": plan,
        "status": "pending",
        "expires_at": None,
        "updated_at": iso(now_utc())
    }, on_conflict="wa_phone").execute()

# ------------------------------------------------------------
# Credits (tables: ai_credits, ai_credit_topups)
# ------------------------------------------------------------
def get_credit_row(wa_phone: str) -> Dict[str, Any]:
    wa_phone = normalize_phone(wa_phone)
    try:
        res = (
            supabase.table("ai_credits")
            .select("*")
            .eq("wa_phone", wa_phone)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        return rows[0] if rows else {}
    except Exception:
        logging.exception("get_credit_row failed")
        return {}

def allocate_subscription_credits(wa_phone: str, plan: str, expires_at_iso: str) -> None:
    """
    Add credits to ai_credits. Credits expire at subscription expiry.
    """
    wa_phone = normalize_phone(wa_phone)
    plan = (plan or "").strip().lower()
    rule = PLAN_RULES.get(plan) or PLAN_RULES["monthly"]
    add = int(rule.get("ai_credits") or 0)

    if add <= 0:
        return

    try:
        current = get_credit_row(wa_phone)
        bal = safe_int(current.get("balance"), 0)
        new_bal = bal + add

        supabase.table("ai_credits").upsert({
            "wa_phone": wa_phone,
            "balance": new_bal,
            "expires_at": expires_at_iso,
            "updated_at": iso(now_utc()),
        }, on_conflict="wa_phone").execute()

        logging.info(f"CREDITS_ALLOC wa_phone={wa_phone} add={add} new_balance={new_bal} exp={expires_at_iso}")
    except Exception:
        logging.exception("allocate_subscription_credits failed")

def debit_ai_credit(wa_phone: str, n: int = 1) -> bool:
    """
    Decrement ai credits by n if available and not expired.
    """
    wa_phone = normalize_phone(wa_phone)
    try:
        row = get_credit_row(wa_phone)
        bal = safe_int(row.get("balance"), 0)
        exp = parse_iso_dt(row.get("expires_at"))
        if exp and exp <= now_utc():
            # expired => treat as 0
            bal = 0

        if bal < n:
            return False

        new_bal = bal - n
        supabase.table("ai_credits").update({
            "balance": new_bal,
            "updated_at": iso(now_utc()),
        }).eq("wa_phone", wa_phone).execute()

        return True
    except Exception:
        logging.exception("debit_ai_credit failed")
        return False

def add_topup_credits(wa_phone: str, credits: int, note: str = "manual") -> None:
    """
    Manual topup endpoint for now; later connect to Paystack.
    """
    wa_phone = normalize_phone(wa_phone)
    credits = int(credits)
    if credits <= 0:
        return

    try:
        # log topup
        try:
            supabase.table("ai_credit_topups").insert({
                "wa_phone": wa_phone,
                "credits": credits,
                "note": note,
                "created_at": iso(now_utc()),
            }).execute()
        except Exception:
            # table may have different columns; ignore logging if insert fails
            pass

        # extend credits expiry:
        # if user has active subscription, keep subscription expiry
        sub = get_subscription_status(wa_phone)
        exp_iso = sub.get("expires_at") if sub.get("active") else None

        current = get_credit_row(wa_phone)
        bal = safe_int(current.get("balance"), 0)
        new_bal = bal + credits

        payload = {
            "wa_phone": wa_phone,
            "balance": new_bal,
            "updated_at": iso(now_utc()),
        }
        if exp_iso:
            payload["expires_at"] = exp_iso
        else:
            # non-subscriber: give a reasonable expiry window for topup credits
            payload["expires_at"] = iso(now_utc() + timedelta(days=90))

        supabase.table("ai_credits").upsert(payload, on_conflict="wa_phone").execute()
        logging.info(f"CREDITS_TOPUP wa_phone={wa_phone} add={credits} new_balance={new_bal}")
    except Exception:
        logging.exception("add_topup_credits failed")

# ------------------------------------------------------------
# Daily usage limiting (tables: ai_daily_usage, ai_daily_quota)
# ------------------------------------------------------------
def get_daily_total_usage(wa_phone: str) -> int:
    wa_phone = normalize_phone(wa_phone)
    d = today_key_utc()
    try:
        res = (
            supabase.table("ai_daily_usage")
            .select("count")
            .eq("wa_phone", wa_phone)
            .eq("day", d)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return 0
        return safe_int(rows[0].get("count"), 0)
    except Exception:
        # If schema differs, fail open but log
        logging.exception("get_daily_total_usage failed")
        return 0

def inc_daily_total_usage(wa_phone: str, inc: int = 1) -> None:
    wa_phone = normalize_phone(wa_phone)
    d = today_key_utc()
    try:
        current = get_daily_total_usage(wa_phone)
        new_val = current + inc
        supabase.table("ai_daily_usage").upsert({
            "wa_phone": wa_phone,
            "day": d,
            "count": new_val,
            "updated_at": iso(now_utc()),
        }, on_conflict="wa_phone,day").execute()
    except Exception:
        logging.exception("inc_daily_total_usage failed")

def get_daily_ai_usage(wa_phone: str) -> int:
    wa_phone = normalize_phone(wa_phone)
    d = today_key_utc()
    try:
        res = (
            supabase.table("ai_daily_usage")
            .select("ai_count")
            .eq("wa_phone", wa_phone)
            .eq("day", d)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return 0
        return safe_int(rows[0].get("ai_count"), 0)
    except Exception:
        return 0

def inc_daily_ai_usage(wa_phone: str, inc: int = 1) -> None:
    wa_phone = normalize_phone(wa_phone)
    d = today_key_utc()
    try:
        # read current row (maybe exists)
        res = (
            supabase.table("ai_daily_usage")
            .select("count,ai_count")
            .eq("wa_phone", wa_phone)
            .eq("day", d)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if rows:
            count = safe_int(rows[0].get("count"), 0)
            ai_count = safe_int(rows[0].get("ai_count"), 0)
        else:
            count = 0
            ai_count = 0

        supabase.table("ai_daily_usage").upsert({
            "wa_phone": wa_phone,
            "day": d,
            "count": count,  # total count handled separately in inc_daily_total_usage
            "ai_count": ai_count + inc,
            "updated_at": iso(now_utc()),
        }, on_conflict="wa_phone,day").execute()
    except Exception:
        # table may not have ai_count; ignore
        pass

# ------------------------------------------------------------
# Q&A sources
# 1) qa_library (curated 1500)
# 2) qa_cache (learned cache)
# ------------------------------------------------------------
def qa_library_get(question: str) -> Optional[str]:
    nq = normalize_question(question)
    if not nq:
        return None
    try:
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
        return rows[0].get("answer")
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
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return None

        row = rows[0]
        ans = row.get("answer")

        # best-effort increment
        try:
            cid = row.get("id")
            use_count = safe_int(row.get("use_count"), 0) + 1
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
        # ignore if insert fails (duplicate/unique or schema mismatch)
        return

# ------------------------------------------------------------
# AI Answer (OpenAI optional)
# ------------------------------------------------------------
def ai_answer(question: str) -> str:
    # If OpenAI not configured, fall back to safe stub
    if not AI_ENABLED:
        return "AI is currently disabled. Please try again later."
    if not OPENAI_API_KEY:
        return (
            "AI is enabled but OPENAI_API_KEY is not set on the server.\n"
            "Please try again later."
        )

    # Minimal OpenAI call via HTTPS (keeps dependencies low)
    try:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": OPENAI_MODEL,
            "messages": [
                {"role": "system", "content": "You are Naija Tax Guide, an assistant that explains Nigerian tax concepts clearly and simply. Keep answers short, practical, and accurate."},
                {"role": "user", "content": question},
            ],
            "temperature": 0.2,
        }
        r = requests.post(url, headers=headers, json=payload, timeout=25)
        if r.status_code >= 300:
            logging.warning(f"OPENAI_FAIL status={r.status_code} body={r.text[:200]}")
            return "Sorry — AI service is temporarily unavailable. Please try again."

        data = r.json()
        msg = (((data.get("choices") or [])[0]).get("message") or {}).get("content") or ""
        msg = msg.strip()
        return msg if msg else "Sorry — I could not generate a response. Please rephrase your question."
    except Exception:
        logging.exception("ai_answer failed")
        return "Sorry — AI error. Please try again."

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

# ------------------------------------------------------------
# OTP (optional) stored in flow_sessions (best-effort)
# ------------------------------------------------------------
def otp_hash(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()

def otp_store(wa_phone: str, code: str) -> str:
    """
    Store OTP in flow_sessions. If schema differs, we still return a token for client,
    but verification may not work; logs will show.
    """
    token = uuid.uuid4().hex
    exp = iso(now_utc() + timedelta(minutes=OTP_TTL_MINUTES))
    try:
        supabase.table("flow_sessions").insert({
            "session_id": token,
            "wa_phone": normalize_phone(wa_phone),
            "kind": "otp",
            "code_hash": otp_hash(code),
            "expires_at": exp,
            "created_at": iso(now_utc()),
        }).execute()
    except Exception:
        logging.exception("otp_store failed (flow_sessions schema may differ)")
    return token

def otp_verify(wa_phone: str, token: str, code: str) -> bool:
    try:
        res = (
            supabase.table("flow_sessions")
            .select("*")
            .eq("session_id", token)
            .eq("wa_phone", normalize_phone(wa_phone))
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return False
        row = rows[0]
        exp = parse_iso_dt(row.get("expires_at"))
        if exp and exp <= now_utc():
            return False
        return (row.get("code_hash") or "") == otp_hash(code)
    except Exception:
        logging.exception("otp_verify failed")
        return False

# ------------------------------------------------------------
# Usage gating
# ------------------------------------------------------------
def check_daily_total_limit(wa_phone: str) -> Tuple[bool, str]:
    used = get_daily_total_usage(wa_phone)
    if used >= DAILY_TOTAL_LIMIT:
        return False, f"Daily limit reached ({DAILY_TOTAL_LIMIT}/day). Please try tomorrow."
    return True, "ok"

def can_use_ai(wa_phone: str) -> Tuple[bool, str, Dict[str, Any]]:
    """
    AI permission:
    - If subscribed and has credits (ai_credits.balance), allow.
    - If not subscribed: allow if daily free AI quota not exceeded.
    """
    sub = get_subscription_status(wa_phone)
    credit_row = get_credit_row(wa_phone)

    # subscribers: require credits balance > 0 and not expired
    if sub.get("active"):
        bal = safe_int(credit_row.get("balance"), 0)
        exp = parse_iso_dt(credit_row.get("expires_at") or sub.get("expires_at"))
        if exp and exp <= now_utc():
            bal = 0
        if bal <= 0:
            return False, "AI credits finished. Please top up credits to continue.", {"subscribed": True, "balance": bal}
        return True, "ok", {"subscribed": True, "balance": bal}

    # non-subscribers: free daily AI quota
    used_ai = get_daily_ai_usage(wa_phone)
    if used_ai >= FREE_AI_PER_DAY_NON_SUB:
        return False, "Free daily AI quota finished. Please subscribe to continue.", {"subscribed": False, "free_ai_used": used_ai}
    return True, "ok", {"subscribed": False, "free_ai_used": used_ai}

# ------------------------------------------------------------
# Health / Debug
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({
        "ok": True,
        "service": "naija-tax-guide",
        "time_utc": iso(now_utc()),
        "ai_enabled": AI_ENABLED,
        "require_otp": REQUIRE_OTP,
        "daily_total_limit": DAILY_TOTAL_LIMIT,
        "ai_credits_per_month": AI_CREDITS_PER_MONTH,
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
# AUTH (Web OTP)
# ------------------------------------------------------------
@app.post("/auth/request_otp")
def auth_request_otp():
    body = request.get_json(silent=True) or {}
    wa_phone = normalize_phone(body.get("wa_phone") or "")
    if not wa_phone:
        return jsonify({"ok": False, "error": "wa_phone is required"}), 400

    # generate 6-digit
    code = f"{random.randint(100000, 999999)}"
    token = otp_store(wa_phone, code)

    # send OTP via WhatsApp
    msg = f"Naija Tax Guide login code: {code}\nExpires in {OTP_TTL_MINUTES} minutes."
    ok, info = send_whatsapp_text(wa_phone, msg)

    logging.info(f"OTP_SEND wa_phone={wa_phone} ok={ok} info={info}")
    if not ok:
        return jsonify({"ok": False, "error": info}), 502

    return jsonify({"ok": True, "otp_token": token})

@app.post("/auth/verify_otp")
def auth_verify_otp():
    body = request.get_json(silent=True) or {}
    wa_phone = normalize_phone(body.get("wa_phone") or "")
    otp_token = (body.get("otp_token") or "").strip()
    code = (body.get("code") or "").strip()

    if not wa_phone or not otp_token or not code:
        return jsonify({"ok": False, "error": "wa_phone, otp_token, and code are required"}), 400

    if not otp_verify(wa_phone, otp_token, code):
        return jsonify({"ok": False, "error": "Invalid or expired OTP"}), 401

    # session token (simple)
    session_token = uuid.uuid4().hex
    exp = iso(now_utc() + timedelta(days=7))

    # store session (best-effort)
    try:
        supabase.table("flow_sessions").insert({
            "session_id": session_token,
            "wa_phone": wa_phone,
            "kind": "web_session",
            "expires_at": exp,
            "created_at": iso(now_utc()),
        }).execute()
    except Exception:
        logging.exception("store web_session failed (flow_sessions schema may differ)")

    return jsonify({"ok": True, "session_token": session_token, "expires_at": exp})

def is_session_valid(wa_phone: str, session_token: str) -> bool:
    if not REQUIRE_OTP:
        return True
    if not wa_phone or not session_token:
        return False
    try:
        res = (
            supabase.table("flow_sessions")
            .select("*")
            .eq("session_id", session_token)
            .eq("wa_phone", normalize_phone(wa_phone))
            .eq("kind", "web_session")
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return False
        exp = parse_iso_dt(rows[0].get("expires_at"))
        return (not exp) or (exp > now_utc())
    except Exception:
        return False

# ------------------------------------------------------------
# ASK (Web chat + shared logic)
# ------------------------------------------------------------
@app.post("/ask")
def ask():
    body = request.get_json(silent=True) or {}
    wa_phone = normalize_phone(body.get("wa_phone") or "")
    question = (body.get("question") or "").strip()
    session_token = request.headers.get("x-session-token", "").strip() or (body.get("session_token") or "").strip()

    if not wa_phone:
        return jsonify({"ok": False, "error": "wa_phone is required"}), 400
    if not question:
        return jsonify({"ok": False, "error": "question is required"}), 400

    if REQUIRE_OTP and not is_session_valid(wa_phone, session_token):
        return jsonify({"ok": False, "error": "OTP required. Please login first."}), 401

    # daily total cap (prevents abuse even for cache)
    ok, msg = check_daily_total_limit(wa_phone)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 429

    # 1) qa_library
    lib = qa_library_get(question)
    if lib:
        inc_daily_total_usage(wa_phone, 1)
        return jsonify({"ok": True, "source": "qa_library", "answer": lib})

    # 2) qa_cache
    cached = cache_get(question)
    if cached:
        inc_daily_total_usage(wa_phone, 1)
        return jsonify({"ok": True, "source": "qa_cache", "answer": cached})

    # 3) AI (needs credits or free daily AI quota)
    allowed, reason, meta = can_use_ai(wa_phone)
    if not allowed:
        inc_daily_total_usage(wa_phone, 1)
        return jsonify({"ok": False, "error": reason, "meta": meta}), 402

    # debit credit for subscribers OR consume free AI for non-subs
    sub = get_subscription_status(wa_phone)
    if sub.get("active"):
        if not debit_ai_credit(wa_phone, 1):
            inc_daily_total_usage(wa_phone, 1)
            return jsonify({"ok": False, "error": "AI credits finished. Please top up credits to continue."}), 402
    else:
        inc_daily_ai_usage(wa_phone, 1)

    answer = ai_answer(question)
    cache_set(question, answer)

    # increment total usage after work completes
    inc_daily_total_usage(wa_phone, 1)

    return jsonify({"ok": True, "source": "ai", "answer": answer})

# ------------------------------------------------------------
# Manual topup endpoint (admin only for now)
# Later connect to Paystack for public topups
# ------------------------------------------------------------
@app.post("/admin/credits/topup")
def admin_credits_topup():
    auth = require_admin(request)
    if auth:
        return auth

    body = request.get_json(silent=True) or {}
    wa_phone = normalize_phone(body.get("wa_phone") or "")
    credits = safe_int(body.get("credits"), 0)
    note = (body.get("note") or "manual").strip()

    if not wa_phone or credits <= 0:
        return jsonify({"ok": False, "error": "wa_phone and credits>0 required"}), 400

    add_topup_credits(wa_phone, credits, note=note)
    row = get_credit_row(wa_phone)
    return jsonify({"ok": True, "wa_phone": wa_phone, "balance": safe_int(row.get("balance"), 0), "expires_at": row.get("expires_at")})

# ------------------------------------------------------------
# Paystack: Initialize (subscription purchase)
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

    # 3) Paystack init
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}", "Content-Type": "application/json"}
    payload = {
        "email": email,
        "amount": amount_kobo,
        "reference": reference,
        "metadata": {"wa_phone": wa_phone, "plan": plan}
    }
    if PAYSTACK_CALLBACK_URL:
        payload["callback_url"] = PAYSTACK_CALLBACK_URL

    r = requests.post("https://api.paystack.co/transaction/initialize", headers=headers, json=payload, timeout=25)

    try:
        data = r.json()
    except Exception:
        try:
            supabase.table("payments").update({"status": "failed"}).eq("reference", reference).execute()
        except Exception:
            pass
        return jsonify({"ok": False, "error": f"Paystack non-JSON response: {r.text[:200]}"}), 502

    if r.status_code >= 300 or not data.get("status"):
        try:
            supabase.table("payments").update({"status": "failed"}).eq("reference", reference).execute()
        except Exception:
            pass
        msg = data.get("message") or f"HTTP {r.status_code}"
        return jsonify({"ok": False, "error": f"Paystack init failed: {msg}"}), 400

    auth_url = (data.get("data") or {}).get("authorization_url")
    return jsonify({"ok": True, "reference": reference, "authorization_url": auth_url})

# ------------------------------------------------------------
# Paystack: Webhook (activate subscription + allocate credits)
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

    try:
        pay_row = supabase.table("payments").select("*").eq("reference", reference).limit(1).execute()
        rows = pay_row.data or []
    except Exception:
        rows = []

    if not rows:
        logging.warning(f"Webhook reference not found in payments: {reference}")
        return "ok", 200

    pay = rows[0]
    wa_phone = pay.get("wa_phone")
    plan = pay.get("plan")

    meta = data.get("metadata") or {}
    wa_phone = wa_phone or meta.get("wa_phone")
    plan = plan or meta.get("plan")

    if not wa_phone or not plan:
        logging.warning(f"Webhook missing wa_phone/plan for reference={reference}")
        return "ok", 200

    if is_success:
        amount_kobo = safe_int(data.get("amount") or pay.get("amount_kobo") or 0)
        amount = amount_kobo / 100.0

        try:
            supabase.table("payments").update({
                "status": "success",
                "paid_at": iso(now_utc()),
                "amount_kobo": amount_kobo,
                "amount": amount,
                "currency": data.get("currency") or pay.get("currency") or "NGN",
            }).eq("reference", reference).execute()
        except Exception:
            pass

        # Activate + allocate credits
        activate_user_subscription(wa_phone, plan)

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

    # Log inbound webhook hit
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
            # daily total cap applies to WA also
            ok, reason = check_daily_total_limit(from_phone)
            if not ok:
                send_whatsapp_text(from_phone, reason)
                return "ok", 200

            # 1) qa_library
            lib = qa_library_get(text_body)
            if lib:
                inc_daily_total_usage(from_phone, 1)
                ok2, info2 = send_whatsapp_text(from_phone, lib)
                logging.info(f"WA_REPLY_LIBRARY ok={ok2} info={info2}")
                return "ok", 200

            # 2) qa_cache
            cached = cache_get(text_body)
            if cached:
                inc_daily_total_usage(from_phone, 1)
                ok2, info2 = send_whatsapp_text(from_phone, cached)
                logging.info(f"WA_REPLY_CACHE ok={ok2} info={info2}")
                return "ok", 200

            # 3) AI
            allowed, msg2, meta = can_use_ai(from_phone)
            if not allowed:
                inc_daily_total_usage(from_phone, 1)
                send_whatsapp_text(from_phone, msg2)
                logging.info(f"WA_REPLY_NOAI reason={msg2}")
                return "ok", 200

            sub = get_subscription_status(from_phone)
            if sub.get("active"):
                if not debit_ai_credit(from_phone, 1):
                    inc_daily_total_usage(from_phone, 1)
                    send_whatsapp_text(from_phone, "AI credits finished. Please top up credits to continue.")
                    return "ok", 200
            else:
                inc_daily_ai_usage(from_phone, 1)

            answer = ai_answer(text_body)
            cache_set(text_body, answer)
            inc_daily_total_usage(from_phone, 1)

            ok2, info2 = send_whatsapp_text(from_phone, answer)
            logging.info(f"WA_REPLY_AI ok={ok2} info={info2}")

            return "ok", 200

    # Status updates
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

@app.get("/admin/credits")
def admin_credits():
    auth = require_admin(request)
    if auth:
        return auth

    wa_phone = normalize_phone(request.args.get("wa_phone") or "")
    q = supabase.table("ai_credits").select("*")
    if wa_phone:
        q = q.eq("wa_phone", wa_phone)
    res = q.execute()
    return jsonify(res.data or [])
