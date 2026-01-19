# app/main.py
import os
import re
import json
import hmac
import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone, date
from typing import Any, Optional, Dict, Tuple, List

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client

# ------------------------------------------------------------
# App
# ------------------------------------------------------------
app = Flask(__name__)

# ------------------------------------------------------------
# Error logging (ensures stack traces show in Koyeb logs)
# ------------------------------------------------------------
@app.errorhandler(Exception)
def _unhandled_exception_handler(e):
    try:
        logging.exception("Unhandled exception: %s", e)
    except Exception:
        pass
    return jsonify({"ok": False, "error": "internal_error"}), 500


# Ensure logs always go to stdout on Koyeb (Gunicorn captures stdout/stderr)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    force=True,
)

# Basic request logging so Koyeb logs show activity
@app.before_request
def _log_request():
    try:
        logging.info("REQ %s %s", request.method, request.path)
    except Exception:
        pass

@app.after_request
def _log_response(resp):
    try:
        logging.info("RES %s %s -> %s", request.method, request.path, resp.status_code)
    except Exception:
        pass
    return resp

@app.errorhandler(Exception)
def _handle_unexpected(err):
    # Always log stacktrace, but return a safe message to the client
    logging.exception("Unhandled error: %s", err)
    return jsonify({"ok": False, "error": "Something went wrong while processing your request. Please try again."}), 500

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
WHATSAPP_BUSINESS_ACCOUNT_ID = os.getenv("WHATSAPP_BUSINESS_ACCOUNT_ID", "").strip()

# OpenAI (AI + TTS)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()
OPENAI_TTS_MODEL = os.getenv("OPENAI_TTS_MODEL", "gpt-4o-mini-tts").strip()
OPENAI_TTS_VOICE = os.getenv("OPENAI_TTS_VOICE", "alloy").strip()

# Storage (Supabase Storage)
VOICE_BUCKET = os.getenv("VOICE_BUCKET", "voice-help content").strip()
SUPABASE_STORAGE_URL = os.getenv("SUPABASE_STORAGE_URL", "").strip()  # optional
VOICE_PUBLIC_BASE = os.getenv("VOICE_PUBLIC_BASE", "").strip()

# Usage limits
FREE_DAILY_TOTAL_LIMIT = int(os.getenv("FREE_DAILY_TOTAL_LIMIT", "30").strip())
PAID_DAILY_TOTAL_LIMIT = int(os.getenv("PAID_DAILY_TOTAL_LIMIT", "2000").strip())

# Credits (locked business rules)
MONTHLY_AI_CREDITS = 300
VOICE_AI_COST = 3
TEXT_AI_COST = 1
VOICE_CACHED_FIRST_GEN_COST = 1

# CORS
CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:3000").strip()
allowed_origins = [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]

CORS(
    app,
    resources={r"/*": {"origins": allowed_origins}},
    supports_credentials=False,
    allow_headers=["Content-Type", "x-admin-key"],
    methods=["GET", "POST", "OPTIONS"],
)


@app.before_request
def _log_incoming_request():
    # Confirms requests are reaching Koyeb even if something fails later.
    try:
        logging.info("REQ %s %s", request.method, request.path)
    except Exception:
        pass


@app.after_request
def _log_response(resp):
    try:
        logging.info("RES %s %s -> %s", request.method, request.path, resp.status_code)
    except Exception:
        pass
    return resp

# ------------------------------------------------------------
# Supabase client
# ------------------------------------------------------------
if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    logging.warning("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing. DB calls will fail.")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# ------------------------------------------------------------
# Plans
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

def today_utc() -> date:
    return now_utc().date()

def require_admin(req):
    key = req.headers.get("x-admin-key", "")
    if not ADMIN_API_KEY or key != ADMIN_API_KEY:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return None

def normalize_phone(raw: str) -> str:
    s = (raw or "").strip()
    s = s.replace(" ", "").replace("+", "")
    return s

def normalize_question(q: str) -> str:
    # punctuation-proof normalization
    s = (q or "").strip().lower()
    s = re.sub(r"[^a-z0-9\s]", " ", s)   # remove punctuation/symbols
    s = re.sub(r"\s+", " ", s).strip()   # collapse spaces
    return s

def safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default

def parse_iso_dt(s: Any) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None

# ------------------------------------------------------------
# Subscription (user_subscriptions)
# ------------------------------------------------------------
def get_subscription_row(wa_phone: str) -> Optional[Dict[str, Any]]:
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
        return rows[0] if rows else None
    except Exception:
        logging.exception("get_subscription_row failed")
        return None

def is_subscription_active(sub: Optional[Dict[str, Any]]) -> bool:
    if not sub:
        return False
    status = (sub.get("status") or "").lower()
    if status != "active":
        return False
    exp = parse_iso_dt(sub.get("expires_at"))
    if not exp:
        return False
    return exp > now_utc()

def get_plan_expiry_iso(wa_phone: str) -> Optional[str]:
    sub = get_subscription_row(wa_phone)
    if not is_subscription_active(sub):
        return None
    exp = parse_iso_dt(sub.get("expires_at"))
    return iso(exp) if exp else None

def plan_days(plan: str) -> int:
    return safe_int(PLAN_RULES.get(plan, {}).get("days"), 30)

def plan_total_credits(plan: str) -> int:
    # 300 credits per month across all plans
    d = plan_days(plan)
    if d >= 360:
        months = 12
    elif d >= 80:
        months = 3
    else:
        months = 1
    return MONTHLY_AI_CREDITS * months

def plan_period_start(sub: Dict[str, Any]) -> Optional[datetime]:
    exp = parse_iso_dt(sub.get("expires_at"))
    if not exp:
        return None
    d = plan_days((sub.get("plan") or "monthly").lower())
    return exp - timedelta(days=d)

# ------------------------------------------------------------
# Usage enforcement: daily total answers
# ------------------------------------------------------------
def daily_total_usage_get(wa_phone: str) -> int:
    try:
        res = (
            supabase.table("daily_answer_usage")
            .select("total_count")
            .eq("wa_phone", normalize_phone(wa_phone))
            .eq("day", str(today_utc()))
            .limit(1)
            .execute()
        )
        rows = res.data or []
        return safe_int(rows[0].get("total_count"), 0) if rows else 0
    except Exception:
        logging.exception("daily_total_usage_get failed")
        return 0

def daily_total_usage_inc(wa_phone: str, inc: int = 1) -> None:
    try:
        wa_phone = normalize_phone(wa_phone)
        d = str(today_utc())
        res = (
            supabase.table("daily_answer_usage")
            .select("total_count")
            .eq("wa_phone", wa_phone)
            .eq("day", d)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if rows:
            new_val = safe_int(rows[0].get("total_count"), 0) + inc
            supabase.table("daily_answer_usage").update({
                "total_count": new_val,
                "last_used_at": iso(now_utc()),
            }).eq("wa_phone", wa_phone).eq("day", d).execute()
        else:
            supabase.table("daily_answer_usage").insert({
                "wa_phone": wa_phone,
                "day": d,
                "total_count": inc,
                "last_used_at": iso(now_utc()),
            }).execute()
    except Exception:
        logging.exception("daily_total_usage_inc failed")

# ai_daily_usage (count, ai_count)
def ai_daily_usage_inc(wa_phone: str, total_inc: int = 1, ai_inc: int = 0) -> None:
    try:
        wa_phone = normalize_phone(wa_phone)
        d = str(today_utc())
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
            cur_count = safe_int(rows[0].get("count"), 0)
            cur_ai = safe_int(rows[0].get("ai_count"), 0)
            supabase.table("ai_daily_usage").update({
                "count": cur_count + total_inc,
                "ai_count": cur_ai + ai_inc,
                "last_used_at": iso(now_utc()),
            }).eq("wa_phone", wa_phone).eq("day", d).execute()
        else:
            supabase.table("ai_daily_usage").insert({
                "wa_phone": wa_phone,
                "day": d,
                "count": total_inc,
                "ai_count": ai_inc,
                "last_used_at": iso(now_utc()),
            }).execute()
    except Exception:
        logging.exception("ai_daily_usage_inc failed")

# ------------------------------------------------------------
# Credit ledger
# ------------------------------------------------------------
def ledger_add(wa_phone: str, kind: str, credits_delta: int, meta: Optional[Dict[str, Any]] = None) -> None:
    try:
        supabase.table("ai_credit_ledger").insert({
            "wa_phone": normalize_phone(wa_phone),
            "event_at": iso(now_utc()),
            "kind": kind,
            "credits_delta": int(credits_delta),
            "meta": meta or {},
        }).execute()
    except Exception:
        logging.exception("ledger_add failed")

def credits_used_in_period(wa_phone: str, start: datetime, end: datetime) -> int:
    try:
        res = (
            supabase.table("ai_credit_ledger")
            .select("credits_delta,event_at")
            .eq("wa_phone", normalize_phone(wa_phone))
            .gte("event_at", iso(start))
            .lte("event_at", iso(end))
            .execute()
        )
        rows = res.data or []
        used = 0
        for r in rows:
            delta = safe_int(r.get("credits_delta"), 0)
            if delta < 0:
                used += abs(delta)
        return used
    except Exception:
        logging.exception("credits_used_in_period failed")
        return 0

def topups_in_period(wa_phone: str, start: datetime, end: datetime) -> int:
    try:
        res = (
            supabase.table("ai_credit_ledger")
            .select("credits_delta,event_at")
            .eq("wa_phone", normalize_phone(wa_phone))
            .gte("event_at", iso(start))
            .lte("event_at", iso(end))
            .execute()
        )
        rows = res.data or []
        added = 0
        for r in rows:
            delta = safe_int(r.get("credits_delta"), 0)
            if delta > 0:
                added += delta
        return added
    except Exception:
        logging.exception("topups_in_period failed")
        return 0

def credit_balance_for_user(wa_phone: str) -> Dict[str, Any]:
    # internal, not returned to regular users
    sub = get_subscription_row(wa_phone)
    active = is_subscription_active(sub)
    if not active:
        return {"active": False, "remaining": 0}

    plan = (sub.get("plan") or "monthly").lower()
    period_end = parse_iso_dt(sub.get("expires_at")) or now_utc()
    period_start = plan_period_start(sub) or (period_end - timedelta(days=plan_days(plan)))

    allowance = plan_total_credits(plan)
    used = credits_used_in_period(wa_phone, period_start, period_end)
    added = topups_in_period(wa_phone, period_start, period_end)
    remaining = max(0, allowance + added - used)

    return {
        "active": True,
        "plan": plan,
        "period_start": iso(period_start),
        "period_end": iso(period_end),
        "allowance": allowance,
        "used": used,
        "topups": added,
        "remaining": remaining,
    }

# ------------------------------------------------------------
# QA matching: synonyms + expansions
# ------------------------------------------------------------
SYNONYMS: Dict[str, List[str]] = {
    "vat": ["value added tax", "value-added tax"],
    "value added tax": ["vat", "value-added tax"],

    "paye": ["pay as you earn", "pay-as-you-earn"],
    "pay as you earn": ["paye", "pay-as-you-earn"],

    "tin": ["tax identification number"],
    "tax identification number": ["tin"],

    "firs": ["federal inland revenue service"],
    "federal inland revenue service": ["firs"],

    "withholding tax": ["wht"],
    "wht": ["withholding tax"],

    "personal income tax": ["pit"],
    "pit": ["personal income tax"],

    "company income tax": ["cit"],
    "cit": ["company income tax"],

    "capital gains tax": ["cgt"],
    "cgt": ["capital gains tax"],
}


# ------------------------------------------------------------
# Multilingual Answers (Library)
# ------------------------------------------------------------
SUPPORTED_LANGS = ("en", "pcm", "yo", "ig", "ha")
ANSWER_COLS = "answer,answer_en,answer_pcm,answer_yo,answer_ig,answer_ha"


# -----------------------------
# Answer selection by language
# -----------------------------
LANG_TO_COL = {
    "en": "answer_en",
    "pcm": "answer_pcm",
    "yo": "answer_yo",
    "ig": "answer_ig",
    "ha": "answer_ha",
}

# Some legacy schemas may have duplicated columns (e.g., answer_pidgin, answer_hausa, answer_yoruba, answer_igbo).
LEGACY_FALLBACK_COLS = {
    "pcm": ["answer_pidgin"],
    "ha": ["answer_hausa"],
    "yo": ["answer_yoruba"],
    "ig": ["answer_igbo"],
}

def pick_answer(row: dict, lang: str) -> str:
    """Pick the best answer text for the requested language with safe fallbacks."""
    lang = (lang or "en").lower().strip()
    # 1) language-specific
    col = LANG_TO_COL.get(lang, "answer_en")
    v = (row.get(col) or "").strip() if isinstance(row, dict) else ""
    if v:
        return v
    # 1b) legacy aliases
    for c in LEGACY_FALLBACK_COLS.get(lang, []):
        v = (row.get(c) or "").strip()
        if v:
            return v
    # 2) English
    v = (row.get("answer_en") or "").strip()
    if v:
        return v
    # 3) old single-column answer
    return (row.get("answer") or "").strip()

    lang = (lang or "en").strip().lower()
    if lang not in SUPPORTED_LANGS:
        lang = "en"

    # Prefer explicit language column if present
    key = f"answer_{lang}"
    v = (row.get(key) or "").strip() if isinstance(row.get(key), str) else row.get(key)
    if v:
        return v

    # Fallback to English
    v = (row.get("answer_en") or "").strip() if isinstance(row.get("answer_en"), str) else row.get("answer_en")
    if v:
        return v

    # Legacy
    v = (row.get("answer") or "").strip() if isinstance(row.get("answer"), str) else row.get("answer")
    if v:
        return v

    return None


def expand_queries(nq: str) -> List[str]:
    out = [nq]
    joined = nq
    for k, alts in SYNONYMS.items():
        k_norm = normalize_question(k)
        if k_norm and k_norm in joined:
            for alt in alts:
                alt_norm = normalize_question(alt)
                if alt_norm:
                    out.append(normalize_question(joined.replace(k_norm, alt_norm)))
    uniq: List[str] = []
    seen = set()
    for s in out:
        if s and s not in seen:
            uniq.append(s)
            seen.add(s)
    return uniq

# ------------------------------------------------------------
# Typo-tolerant search via Supabase RPC (pg_trgm similarity)
# You must create the SQL functions in Supabase:
#  - qa_help content_search(norm_query text, min_sim real, limit_n int)
#  - qa_help content_search(norm_query text, min_sim real, limit_n int)
# If functions are not present, code safely falls back.
# ------------------------------------------------------------

_RPC_MISSING = set()

def _rpc_best_answer(fn_name: str, norm_query: str, lang: str = "en") -> Optional[str]:
    if not ENABLE_TYPO_TOLERANT:
        return None
    if not norm_query:
        return None
    if fn_name in _RPC_MISSING:
        return None
    try:
        res = supabase.rpc(fn_name, {
            "norm_query": norm_query,
            "min_sim": SIMILARITY_MIN,
            "limit_n": 5
        }).execute()
        rows = res.data or []
        if rows:
            # expects rows like: {answer: "...", score: 0.42, normalized_question: "..."}
            return pick_answer(rows[0], lang)
        return None
    except Exception as e:
        # Function might not exist yet; avoid spamming logs repeatedly
        msg = str(e)
        if "function" in msg and ("does not exist" in msg or "not found" in msg):
            _RPC_MISSING.add(fn_name)
            logging.warning("RPC %s not found in Supabase. Falling back to non-similarity search.", fn_name)
            return None
        logging.exception("RPC %s failed", fn_name)
        return None

# ------------------------------------------------------------
# QA help content + help content
# ------------------------------------------------------------
def help content_get(question: str, lang: str = "en") -> Optional[str]:
    nq = normalize_question(question)
    if not nq:
        return None

    candidates = expand_queries(nq)

    try:
        # 1) exact match
        for c in candidates:
            res = (
                supabase.table("qa_help content")
                .select(f"{ANSWER_COLS},enabled,priority,normalized_question")
                .eq("normalized_question", c)
                .eq("enabled", True)
                .order("priority", desc=True)
                .limit(1)
                .execute()
            )
            rows = res.data or []
            if rows:
                return pick_answer(rows[0], lang)

        # 1b) typo-tolerant similarity match (pg_trgm via RPC)
        ans_sim = _rpc_best_answer("qa_help content_search", candidates[0], lang)
        if ans_sim:
            return ans_sim

        # 2) contains match (ILIKE) + scoring
        tokens = nq.split()

        # Use longer keywords to avoid bad substring matches (e.g., "tin" matching "maintain").
        SAFE_ACRONYMS = {"vat", "tin", "paye", "wht", "firs", "pit", "cit", "cgt"}
        keywords = [t for t in tokens if (len(t) >= 4) or (t in SAFE_ACRONYMS)]
        if not keywords:
            keywords = tokens

        # Keep it small to protect DB performance
        keywords = keywords[:3]

        best_answer = None
        best_score = -1

        for kw in keywords:
            q = (
                supabase.table("qa_help content")
                .select(f"{ANSWER_COLS},normalized_question,priority")
                .eq("enabled", True)
            )

            # For short acronyms, try to match as a word boundary using OR patterns.
            if kw in SAFE_ACRONYMS and len(kw) <= 4:
                # matches: "kw ...", "... kw ...", "... kw"
                q = q.or_(
                    f"normalized_question.ilike.{kw} %,normalized_question.ilike.% {kw} %,normalized_question.ilike.% {kw}"
                )
            else:
                q = q.ilike("normalized_question", f"%{kw}%")

            res = q.limit(25).execute()
            rows = res.data or []

            for r in rows:
                cand_q = (r.get("normalized_question") or "")
                cand_tokens = set(cand_q.split())
                pri = safe_int(r.get("priority"), 0)

                hits = sum(1 for k in keywords if k in cand_tokens)

                # score: prioritize more keyword hits, then priority, then slightly prefer shorter (more specific) questions
                score = (hits * 100) + (pri * 5) - (min(len(cand_q), 160) // 10)

                if score > best_score:
                    best_score = score
                    best_answer = pick_answer(r, lang)

        return best_answer

    except Exception:
        logging.exception("help content_get failed")
        return None

def help content_get(question: str, lang: str = "en") -> Optional[str]:
    nq = normalize_question(question)
    if not nq:
        return None
    try:
        res = (
            supabase.table("qa_help content")
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

        try:
            cid = row.get("id")
            use_count = safe_int(row.get("use_count"), 0) + 1
            if cid:
                supabase.table("qa_help content").update({
                    "use_count": use_count,
                    "last_used_at": iso(now_utc()),
                }).eq("id", cid).execute()
        except Exception:
            pass

        return ans
    except Exception:
        logging.exception("help content_get failed")
        return None

def help content_set(question: str, answer: str) -> None:
    nq = normalize_question(question)
    if not nq or not (answer or "").strip():
        return
    try:
        supabase.table("qa_help content").insert({
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
# OpenAI AI Answer (text)
# ------------------------------------------------------------
def ai_answer_text(question: str, lang: str = "en") -> str:
    if not OPENAI_API_KEY:
        return "Service is temporarily unavailable. Please try again later."

    sys = (
        "You are Naija Hustle Tax Guide. Provide clear, simple, Nigeria-focused tax guidance. "
        "Avoid jargon unless necessary. Use short bullet points when helpful. "
        "If unsure, say so and advise confirming with FIRS/State IRS or a professional."
    )

    # Language output (for multi-language expansion: English, Pidgin, Yoruba, Igbo, Hausa)
    # Note: Library answers are currently stored in English; this only affects AI-generated responses.
    lang = (lang or "en").strip().lower()
    if lang in ("pidgin", "pigin", "naija", "naija pidgin"):
        lang = "pcm"
    if lang in ("yoruba", "yo"):
        lang = "yo"
    if lang in ("igbo", "ig"):
        lang = "ig"
    if lang in ("hausa", "ha"):
        lang = "ha"

    if lang == "pcm":
        sys += "\nRespond in Nigerian Pidgin (clear and respectful)."
    elif lang == "yo":
        sys += "\nRespond in Yoruba (simple and clear)."
    elif lang == "ig":
        sys += "\nRespond in Igbo (simple and clear)."
    elif lang == "ha":
        sys += "\nRespond in Hausa (simple and clear)."
    else:
        sys += "\nRespond in English."

    try:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
        payload = {
            "model": OPENAI_MODEL,
            "messages": [
                {"role": "system", "content": sys},
                {"role": "user", "content": (question or "").strip()[:2000]},
            ],
            "temperature": 0.2,
        }
        r = requests.post(url, headers=headers, json=payload, timeout=35)
        if r.status_code >= 300:
            logging.warning(f"OpenAI error {r.status_code}: {r.text[:200]}")
            return "Sorry — I couldn’t generate an AI answer right now. Please try again."
        data = r.json()
        msg = (((data.get("choices") or [])[0].get("message") or {}).get("content") or "").strip()
        return msg or "Sorry — I couldn’t generate an AI answer right now. Please try again."
    except Exception:
        logging.exception("ai_answer_text failed")
        return "Sorry — I couldn’t generate an AI answer right now. Please try again."

# ------------------------------------------------------------
# Voice generation + Supabase Storage upload
# ------------------------------------------------------------
def derive_storage_base() -> str:
    if VOICE_PUBLIC_BASE:
        return VOICE_PUBLIC_BASE.rstrip("/")
    base = SUPABASE_STORAGE_URL.strip() or SUPABASE_URL.strip()
    return (base.rstrip("/") + "/storage/v1/object/public/" + VOICE_BUCKET).rstrip("/")

def supabase_storage_upload(path: str, content_bytes: bytes, content_type: str = "audio/mpeg") -> Optional[str]:
    try:
        base = (SUPABASE_STORAGE_URL.strip() or SUPABASE_URL.strip()).rstrip("/")
        if not base:
            return None
        url = f"{base}/storage/v1/object/{VOICE_BUCKET}/{path.lstrip('/')}"
        headers = {
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
            "Content-Type": content_type,
            "x-upsert": "true",
        }
        r = requests.post(url, headers=headers, data=content_bytes, timeout=45)
        if r.status_code >= 300:
            logging.warning(f"Storage upload failed {r.status_code}: {r.text[:200]}")
            return None
        return f"{derive_storage_base()}/{path.lstrip('/')}"
    except Exception:
        logging.exception("supabase_storage_upload failed")
        return None

def openai_tts(text: str, voice_style: str = "default") -> Optional[bytes]:
    if not OPENAI_API_KEY:
        return None
    try:
        url = "https://api.openai.com/v1/audio/speech"
        headers = {"Authorization": f"Bearer {OPENAI_API_KEY}"}
        payload = {
            "model": OPENAI_TTS_MODEL,
            "voice": OPENAI_TTS_VOICE,
            "input": (text or "")[:2500],
            "format": "mp3",
        }
        r = requests.post(url, headers=headers, json=payload, timeout=60)
        if r.status_code >= 300:
            logging.warning(f"OpenAI TTS error {r.status_code}: {r.text[:200]}")
            return None
        return r.content
    except Exception:
        logging.exception("openai_tts failed")
        return None

def voice_help content_get(nq: str, provider: str, style: str) -> Optional[str]:
    try:
        res = (
            supabase.table("voice_help content")
            .select("id,audio_url,use_count")
            .eq("normalized_question", nq)
            .eq("voice_provider", provider)
            .eq("voice_style", style)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return None
        row = rows[0]
        try:
            vid = row.get("id")
            use_count = safe_int(row.get("use_count"), 0) + 1
            if vid:
                supabase.table("voice_help content").update({
                    "use_count": use_count,
                    "last_used_at": iso(now_utc()),
                }).eq("id", vid).execute()
        except Exception:
            pass
        return row.get("audio_url")
    except Exception:
        logging.exception("voice_help content_get failed")
        return None

def voice_help content_set(nq: str, provider: str, style: str, audio_url: str) -> None:
    try:
        supabase.table("voice_help content").upsert({
            "normalized_question": nq,
            "voice_provider": provider,
            "voice_style": style,
            "audio_url": audio_url,
            "use_count": 0,
            "created_at": iso(now_utc()),
            "last_used_at": iso(now_utc()),
        }, on_conflict="normalized_question,voice_provider,voice_style").execute()
    except Exception:
        logging.exception("voice_help content_set failed")

def ensure_voice_for_text(nq: str, text: str, provider: str, style: str) -> Tuple[Optional[str], bool]:
    help contentd_url = voice_help content_get(nq, provider, style)
    if help contentd_url:
        return help contentd_url, False

    audio_bytes = openai_tts(text, style) if provider == "openai" else None
    if not audio_bytes:
        return None, False

    key = hashlib.sha256(f"{provider}:{style}:{nq}".encode("utf-8")).hexdigest()[:24]
    obj_path = f"{provider}/{style}/{key}.mp3"
    url = supabase_storage_upload(obj_path, audio_bytes, "audio/mpeg")
    if not url:
        return None, False

    voice_help content_set(nq, provider, style, url)
    return url, True

# ------------------------------------------------------------
# Enforcement decisions
# ------------------------------------------------------------
def free_or_paid_daily_limit(wa_phone: str) -> Tuple[int, bool]:
    sub = get_subscription_row(wa_phone)
    active = is_subscription_active(sub)
    return (PAID_DAILY_TOTAL_LIMIT, True) if active else (FREE_DAILY_TOTAL_LIMIT, False)

def enforce_daily_total_limit_or_message(wa_phone: str) -> Optional[str]:
    """Return a user-facing message if today's limit is exceeded (no internal jargon)."""
    limit, is_paid = free_or_paid_daily_limit(wa_phone)
    used = daily_total_usage_get(wa_phone)
    if used >= limit:
        if is_paid:
            return "You’ve reached today’s limit for your plan. Please try again tomorrow or upgrade your plan."
        # Free user (no active subscription)
        return "You’ve reached today’s free plan limit. Please try again tomorrow or subscribe via /pricing for higher access."
    return None

def can_use_ai(wa_phone: str, credits_needed: int) -> Tuple[bool, str, Dict[str, Any]]:
    """AI gating without exposing 'AI' wording to end-users."""
    bal = credit_balance_for_user(wa_phone)

    # If user has no active subscription, we present the same free-limit message
    if not bal.get("active"):
        return False, "You’ve reached today’s free plan limit. Please subscribe via /pricing for higher access.", bal

    # If user is subscribed but has exhausted credits/allowance, present plan-limit message
    if bal.get("remaining", 0) < credits_needed:
        return False, "You’ve reached your current plan limit for this period. Please top up or renew/upgrade via /pricing.", bal

    return True, "ok", bal

# ------------------------------------------------------------
# Core resolver
# ------------------------------------------------------------
def resolve_answer(wa_phone: str, question: str, mode: str, voice_provider: str, voice_style: str, lang: str = "en") -> Dict[str, Any]:
    wa_phone = normalize_phone(wa_phone)
    question = (question or "").strip()
    nq = normalize_question(question)

    msg = enforce_daily_total_limit_or_message(wa_phone)
    if msg:
        return {"ok": True, "answer_text": msg, "audio_url": None, "credits_used": 0, "meta": {"source": "limit"}}

    # 1) help content
    lib_ans = help content_get(question, lang)
    if lib_ans:
        daily_total_usage_inc(wa_phone, 1)
        ai_daily_usage_inc(wa_phone, total_inc=1, ai_inc=0)

        if mode == "voice":
            audio_url, generated_now = ensure_voice_for_text(nq, lib_ans, voice_provider, voice_style)
            credits_used = 0
            if generated_now:
                allowed, _, _ = can_use_ai(wa_phone, VOICE_CACHED_FIRST_GEN_COST)
                if not allowed:
                    return {"ok": True, "answer_text": lib_ans, "audio_url": None, "credits_used": 0, "meta": {"source": "help content", "voice": "blocked"}}
                credits_used = VOICE_CACHED_FIRST_GEN_COST
                ledger_add(wa_phone, "tts_help contentd_gen", -credits_used, {"source": "help content", "nq": nq})
            return {"ok": True, "answer_text": lib_ans, "audio_url": audio_url, "credits_used": credits_used, "meta": {"source": "help content"}}

        return {"ok": True, "answer_text": lib_ans, "audio_url": None, "credits_used": 0, "meta": {"source": "help content"}}

    # 2) help content
    help contentd = help content_get(question)
    if help contentd:
        daily_total_usage_inc(wa_phone, 1)
        ai_daily_usage_inc(wa_phone, total_inc=1, ai_inc=0)

        if mode == "voice":
            audio_url, generated_now = ensure_voice_for_text(nq, help contentd, voice_provider, voice_style)
            credits_used = 0
            if generated_now:
                allowed, _, _ = can_use_ai(wa_phone, VOICE_CACHED_FIRST_GEN_COST)
                if not allowed:
                    return {"ok": True, "answer_text": help contentd, "audio_url": None, "credits_used": 0, "meta": {"source": "help content", "voice": "blocked"}}
                credits_used = VOICE_CACHED_FIRST_GEN_COST
                ledger_add(wa_phone, "tts_help contentd_gen", -credits_used, {"source": "help content", "nq": nq})
            return {"ok": True, "answer_text": help contentd, "audio_url": audio_url, "credits_used": credits_used, "meta": {"source": "help content"}}

        return {"ok": True, "answer_text": help contentd, "audio_url": None, "credits_used": 0, "meta": {"source": "help content"}}

    # 3) AI fallback
    credits_needed = VOICE_AI_COST if mode == "voice" else TEXT_AI_COST
    allowed, reason, _ = can_use_ai(wa_phone, credits_needed)
    if not allowed:
        daily_total_usage_inc(wa_phone, 1)
        ai_daily_usage_inc(wa_phone, total_inc=1, ai_inc=0)
        msg = f"{reason}\n\nPlease subscribe to continue asking questions."
        return {"ok": True, "answer_text": msg, "audio_url": None, "credits_used": 0, "meta": {"source": "ai_blocked"}}

    ans = ai_answer_text(question, lang=lang)
    help content_set(question, ans)

    ledger_kind = "ai_voice" if mode == "voice" else "ai_text"
    ledger_add(wa_phone, ledger_kind, -credits_needed, {"source": "ai", "nq": nq, "model": OPENAI_MODEL})

    daily_total_usage_inc(wa_phone, 1)
    ai_daily_usage_inc(wa_phone, total_inc=1, ai_inc=1)

    if mode == "voice":
        audio_url, _ = ensure_voice_for_text(nq, ans, voice_provider, voice_style)
        return {"ok": True, "answer_text": ans, "audio_url": audio_url, "credits_used": credits_needed, "meta": {"source": "ai"}}

    return {"ok": True, "answer_text": ans, "audio_url": None, "credits_used": credits_needed, "meta": {"source": "ai"}}

# ------------------------------------------------------------
# Health / Debug
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True, "status": "healthy"}), 200


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
# Public: ASK (returns only answer + audio_url + plan_expiry)
# ------------------------------------------------------------
@app.post("/ask")
def ask():
    body = request.get_json(silent=True) or {}
    wa_phone = normalize_phone(body.get("wa_phone") or "")
    question = (body.get("question") or "").strip()

    # Accept either "lang" or "language" from the frontend, default to English.
    lang = (body.get("lang") or body.get("language") or "en").strip().lower()

    mode = (body.get("mode") or "text").strip().lower()
    if mode not in ("text", "voice"):
        mode = "text"

    voice_provider = (body.get("voice_provider") or "openai").strip().lower()
    voice_style = (body.get("voice_style") or "default").strip().lower()

    if not wa_phone:
        return jsonify({"ok": False, "error": "wa_phone is required"}), 400
    if not question:
        return jsonify({"ok": False, "error": "question is required"}), 400

    try:
        logging.info("ASK wa_phone=%s lang=%s mode=%s q=%s", wa_phone, lang, mode, question[:200])
        result = resolve_answer(wa_phone, question, mode, voice_provider, voice_style, lang)
        return jsonify({
            "ok": True,
            "answer": result.get("answer_text"),
            "audio_url": result.get("audio_url"),
            "plan_expiry": get_plan_expiry_iso(wa_phone),
        })
    except Exception as e:
        logging.exception("ASK failed wa_phone=%s lang=%s mode=%s", wa_phone, lang, mode)
        # Never expose internal wording to the end user.
        return jsonify({
            "ok": False,
            "error": "Something went wrong while processing your request. Please try again.",
            "plan_expiry": get_plan_expiry_iso(wa_phone),
        }), 500

# ------------------------------------------------------------
# Paystack: Initialize
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

    try:
        supabase.table("user_subscriptions").upsert({
            "wa_phone": wa_phone,
            "plan": plan,
            "status": "pending",
            "expires_at": None,
            "updated_at": iso(now_utc()),
        }, on_conflict="wa_phone").execute()
    except Exception:
        pass

    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}", "Content-Type": "application/json"}
    payload = {
        "email": email,
        "amount": amount_kobo,
        "reference": reference,
        "metadata": {"wa_phone": wa_phone, "plan": plan},
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
# Paystack: Webhook
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

    pay_row = supabase.table("payments").select("*").eq("reference", reference).limit(1).execute()
    rows = pay_row.data or []
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
        amount_kobo = safe_int(data.get("amount"), safe_int(pay.get("amount_kobo"), 0))
        amount = amount_kobo / 100.0

        supabase.table("payments").update({
            "status": "success",
            "paid_at": iso(now_utc()),
            "amount_kobo": amount_kobo,
            "amount": amount,
            "currency": data.get("currency") or pay.get("currency") or "NGN",
        }).eq("reference", reference).execute()

        expires_at = iso(now_utc() + timedelta(days=plan_days(plan)))
        supabase.table("user_subscriptions").upsert({
            "wa_phone": normalize_phone(wa_phone),
            "plan": plan,
            "status": "active",
            "expires_at": expires_at,
            "updated_at": iso(now_utc()),
        }, on_conflict="wa_phone").execute()

    return "ok", 200

# ------------------------------------------------------------
# Admin endpoints (optional)
# ------------------------------------------------------------
@app.get("/admin/metrics")
def admin_metrics():
    auth = require_admin(request)
    if auth:
        return auth

    try:
        d = str(today_utc())
        usage = supabase.table("ai_daily_usage").select("wa_phone,count,ai_count").eq("day", d).execute().data or []
        total_answers = sum(safe_int(u.get("count"), 0) for u in usage)
        total_ai = sum(safe_int(u.get("ai_count"), 0) for u in usage)
        top = sorted(usage, key=lambda x: safe_int(x.get("count"), 0), reverse=True)[:10]
    except Exception:
        total_answers, total_ai, top = 0, 0, []

    return jsonify({
        "ok": True,
        "day": str(today_utc()),
        "total_answers_today": total_answers,
        "total_ai_calls_today": total_ai,
        "top_users_today": top,
    })

@app.post("/admin/topup")
def admin_topup():
    auth = require_admin(request)
    if auth:
        return auth

    body = request.get_json(silent=True) or {}
    wa_phone = normalize_phone(body.get("wa_phone") or "")
    credits = safe_int(body.get("credits"), 0)

    if not wa_phone or credits <= 0:
        return jsonify({"ok": False, "error": "wa_phone and positive credits required"}), 400

    ref = uuid.uuid4().hex[:10]
    try:
        supabase.table("ai_credit_topups").insert({
            "wa_phone": wa_phone,
            "credits": credits,
            "status": "success",
            "provider": "manual",
            "reference": ref,
            "created_at": iso(now_utc()),
            "paid_at": iso(now_utc()),
        }).execute()
    except Exception:
        pass

    ledger_add(wa_phone, "topup", +credits, {"provider": "manual", "reference": ref})
    return jsonify({"ok": True, "wa_phone": wa_phone, "credits_added": credits, "reference": ref})

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

# ------------------------------------------------------------
# WhatsApp webhook (kept; ignore until you return to WA)
# ------------------------------------------------------------
def wa_api_url(path: str) -> str:
    return f"https://graph.facebook.com/v24.0{path}"

def send_whatsapp_text(to_wa_phone: str, text: str) -> Tuple[bool, str]:
    if not WHATSAPP_TOKEN or not WHATSAPP_PHONE_NUMBER_ID:
        return False, "WHATSAPP_TOKEN or WHATSAPP_PHONE_NUMBER_ID missing"
    to_wa_phone = normalize_phone(to_wa_phone)
    url = wa_api_url(f"/{WHATSAPP_PHONE_NUMBER_ID}/messages")
    headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}", "Content-Type": "application/json"}
    payload = {"messaging_product": "whatsapp", "to": to_wa_phone, "type": "text", "text": {"body": (text or "")[:3800]}}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=25)
        if r.status_code >= 300:
            return False, f"WhatsApp send failed: {r.status_code} {r.text[:250]}"
        return True, "ok"
    except Exception as e:
        return False, f"WhatsApp send exception: {str(e)[:200]}"

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
    logging.info(f"WA_WEBHOOK_HIT keys={list(payload.keys())}")

    try:
        entry = (payload.get("entry") or [])[0]
        change = (entry.get("changes") or [])[0]
        value = change.get("value") or {}
    except Exception:
        return "ok", 200

    messages = value.get("messages") or []
    if messages:
        msg = messages[0]
        from_phone = normalize_phone(msg.get("from") or "")
        msg_type = msg.get("type") or ""

        text_body = ""
        if msg_type == "text":
            text_body = ((msg.get("text") or {}).get("body") or "").strip()

        if from_phone and text_body:
            result = resolve_answer(from_phone, text_body, "text", "openai", "default")
            ok, info = send_whatsapp_text(from_phone, result.get("answer_text") or "OK")
            logging.info(f"WA_REPLY ok={ok} info={info}")

    return "ok", 200
