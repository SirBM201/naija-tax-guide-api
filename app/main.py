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
from werkzeug.exceptions import HTTPException
from flask_cors import CORS
from supabase import create_client

# ------------------------------------------------------------
# App
# ------------------------------------------------------------
app = Flask(__name__)

# Ensure logs always go to stdout on Koyeb (Gunicorn captures stdout/stderr)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    force=True,
)

# ------------------------------------------------------------
# Optional Supabase RPC availability cache
# ------------------------------------------------------------
_RPC_AVAILABLE = None  # None=unknown, False=missing, True=available
_AI_LEDGER_AVAILABLE = None  # None=unknown, False=missing, True=available
_RPC_MISSING_LOGGED = False

def _env_bool(name: str, default: bool = False) -> bool:
    """Parse common truthy/falsey strings from environment variables."""
    raw = os.getenv(name)
    if raw is None:
        return default
    v = raw.strip().lower()
    if v in ("1", "true", "t", "yes", "y", "on"):
        return True
    if v in ("0", "false", "f", "no", "n", "off", ""):
        return False
    # Unknown value -> keep default
    return default

@app.errorhandler(Exception)
def _handle_unexpected(err):
    # Let Flask/Werkzeug handle HTTP errors (404/405/etc.) properly.
    if isinstance(err, HTTPException):
        return jsonify({"ok": False, "error": err.name}), err.code

    # Always log stacktrace, but return a safe message to the client
    logging.exception("Unhandled error: %s", err)
    return jsonify({"ok": False, "error": "Something went wrong while processing your request. Please try again."}), 500

# ------------------------------------------------------------
# ENV
# ------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

# RPC search minimum similarity (used by Supabase RPC qa_library_search)
RPC_MIN_SIM = float(os.getenv("RPC_MIN_SIM", "0.55"))


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
VOICE_BUCKET = os.getenv("VOICE_BUCKET", "voice-cache").strip()
SUPABASE_STORAGE_URL = os.getenv("SUPABASE_STORAGE_URL", "").strip()  # optional
VOICE_PUBLIC_BASE = os.getenv("VOICE_PUBLIC_BASE", "").strip()

# Usage limits
FREE_DAILY_TOTAL_LIMIT = int(os.getenv("FREE_DAILY_TOTAL_LIMIT", "30").strip())
PAID_DAILY_TOTAL_LIMIT = int(os.getenv("PAID_DAILY_TOTAL_LIMIT", "2000").strip())

# Feature toggles (kept server-side; do not expose these words to end users)
ENABLE_QA_CACHE = _env_bool("ENABLE_QA_CACHE", True)
ENABLE_QA_LIBRARY = _env_bool("ENABLE_QA_LIBRARY", True)
ENABLE_TYPO_TOLERANT = _env_bool("ENABLE_TYPO_TOLERANT", True)

# Similarity threshold used by Supabase RPC search functions (pg_trgm similarity)
SIMILARITY_MIN = float(os.getenv("SIMILARITY_MIN", "0.25").strip())

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
# Telegram runtime session (lightweight; best-effort)
# ------------------------------------------------------------
TELEGRAM_SESSIONS: Dict[str, Dict[str, Any]] = {}  # chat_id -> {"email": str|None, "plan": str|None}

def tg_get_session(chat_id: str) -> Dict[str, Any]:
    s = TELEGRAM_SESSIONS.get(chat_id)
    if not s:
        s = {"email": None, "plan": None}
        TELEGRAM_SESSIONS[chat_id] = s
    return s

# ------------------------------------------------------------
# Paystack helpers (used by Web + Telegram)
# ------------------------------------------------------------
def paystack_amount_kobo_for_plan(plan: str) -> int:
    rule = PLAN_RULES.get(plan)
    if not rule:
        raise ValueError("Unknown plan")
    amount_ngn = int(rule.get("price_ngn") or 0)
    if amount_ngn <= 0:
        raise ValueError("Plan price not configured")
    return amount_ngn * 100  # kobo

def create_paystack_authorization_url(email: str, wa_phone: str, plan: str) -> Tuple[bool, str, Optional[str]]:
    """
    Returns: (ok, authorization_url_or_error, reference)
    """
    if not PAYSTACK_SECRET_KEY:
        return False, "PAYSTACK_SECRET_KEY not set", None
    if not email or "@" not in email:
        return False, "Valid email is required for payment", None
    if plan not in PLAN_RULES:
        return False, "Unknown plan", None

    amount_kobo = paystack_amount_kobo_for_plan(plan)

    # Paystack reference must be unique; embed wa_phone for easy tracing
    reference = f"NTG-{uuid.uuid4().hex[:10]}"

    callback = PAYSTACK_CALLBACK_URL or (APP_BASE_URL.rstrip("/") + "/paystack/callback" if APP_BASE_URL else "")

    payload = {
        "email": email,
        "amount": amount_kobo,
        "reference": reference,
        "callback_url": callback if callback else None,
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
            "source": "telegram" if wa_phone.startswith("tg:") else "web",
        },
    }
    # Remove None callback to avoid Paystack complaints
    if payload.get("callback_url") is None:
        payload.pop("callback_url", None)

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    try:
        r = requests.post("https://api.paystack.co/transaction/initialize", headers=headers, json=payload, timeout=25)
        data = r.json() if r.content else {}
        if not r.ok or not data.get("status"):
            return False, (data.get("message") or f"Paystack initialize failed ({r.status_code})"), None

        auth_url = (data.get("data") or {}).get("authorization_url")
        if not auth_url:
            return False, "Paystack did not return authorization_url", None
        return True, auth_url, reference
    except Exception as e:
        return False, f"Paystack error: {e}", None


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
# Markdown output formatter (server-side post-processor)
# ------------------------------------------------------------
DISCLAIMER = (
    "_Disclaimer: This is general guidance. For binding advice, confirm with FIRS / your State IRS "
    "or a qualified tax professional._"
)

_MD_H_RE = re.compile(r"(?m)^\s{0,3}#{1,6}\s+")
_MD_LIST_RE = re.compile(r"(?m)^\s{0,3}(-|\*|\d+\.)\s+")
_MD_TABLE_RE = re.compile(r"(?m)^\s*\|.+\|\s*$")

def _clean_md(text: Optional[str]) -> str:
    t = (text or "").strip()
    t = t.replace("\r\n", "\n").replace("\r", "\n")
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()

def _looks_like_markdown(text: str) -> bool:
    t = (text or "").strip()
    if not t:
        return False
    if _MD_H_RE.search(t):
        return True
    if _MD_LIST_RE.search(t):
        return True
    if _MD_TABLE_RE.search(t):
        return True
    # common emphasis/code markers
    if "```" in t or "**" in t or "_" in t:
        return True
    return False

def strip_markdown_for_tts(md: str) -> str:
    """
    Convert markdown-ish answer to simple readable text for voice.
    (Keeps content; removes headings, bullets, code fences, links formatting.)
    """
    t = _clean_md(md)
    if not t:
        return ""
    # Remove code fences
    t = re.sub(r"```[\s\S]*?```", "", t)
    # Links: [text](url) -> text
    t = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", t)
    # Headings: "### Title" -> "Title"
    t = re.sub(r"(?m)^\s{0,3}#{1,6}\s+", "", t)
    # Bullets -> sentence
    t = re.sub(r"(?m)^\s{0,3}(-|\*|\d+\.)\s+", "- ", t)
    # Bold/italic markers
    t = t.replace("**", "").replace("__", "").replace("*", "").replace("_", "")
    # Collapse whitespace
    t = re.sub(r"\n{3,}", "\n\n", t).strip()
    return t

def format_markdown_answer(question: str, raw_answer: str) -> str:
    """
    Wrap raw answer into a consistent, professional Markdown structure.

    Rules:
    - If the answer already looks like structured Markdown, we keep it and only append a disclaimer once.
    - Otherwise, we wrap it into standard sections.
    """
    q = _clean_md(question)
    a = _clean_md(raw_answer)

    if not a:
        return (
            "### Direct Answer\n"
            "I couldn't generate a reliable answer for that question.\n\n"
            "### What I need from you\n"
            "- Your **state of operation**\n"
            "- Are you an **individual** or a **business**?\n"
            "- What type of income/transaction is involved?\n\n"
            f"{DISCLAIMER}"
        )

    # Avoid duplicating disclaimer
    if "Disclaimer:" in a or "_Disclaimer:" in a:
        return a

    # If already structured, keep it and append disclaimer at end
    if _looks_like_markdown(a):
        return f"{a}\n\n{DISCLAIMER}"

    # Default wrapper
    return (
        f"### Direct Answer\n{a}\n\n"
        "### What to do next\n"
        "- Confirm if this applies to your **state** and your **business type**.\n"
        "- Keep supporting documents (invoices/receipts, bank statements, contracts).\n"
        "- If uncertain, verify with **FIRS / State IRS** before filing.\n\n"
        "### Documents to keep\n"
        "- Invoices / receipts\n"
        "- Bank statements\n"
        "- Contracts / engagement letters\n"
        "- Payment evidence / schedules\n\n"
        "### Common mistakes\n"
        "- Filing without confirming the correct authority (FIRS vs State IRS)\n"
        "- Poor record keeping (missing invoices/receipts)\n"
        "- Mixing personal and business transactions without documentation\n\n"
        f"{DISCLAIMER}"
    )

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

def ledger_add(wa_phone: str, delta: int, reason: str) -> None:
    """Add a credit ledger entry if the table exists; otherwise no-op."""
    try:
        supabase.table("ai_credit_ledger").insert({
            "wa_phone": wa_phone,
            "credits_delta": int(delta),
            "reason": reason,
            "event_at": iso(now_utc()),
        }).execute()
    except Exception as e:
        logging.warning("ledger_add failed (non-fatal): %s", e)
        return
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
# ------------------------------------------------------------
_RPC_MISSING = set()

def _rpc_best_answer(fn_name: str, norm_query: str, lang: str = "en") -> Optional[str]:
    """Try pg_trgm RPC if it exists. If not present, fail silently.

    This avoids hard-failing deployments where the function hasn't been created in Supabase.
    """
    global _RPC_AVAILABLE, _RPC_MISSING_LOGGED

    if not ENABLE_TYPO_TOLERANT:
        return None
    if not norm_query:
        return None

    if _RPC_AVAILABLE is False:
        return None

    try:
        res = supabase.rpc(fn_name, {
            "norm_query": norm_query,
            "limit_n": 1,
            "min_sim": RPC_MIN_SIM,
        }).execute()
        rows = res.data or []
        if rows:
            row = rows[0]
            _RPC_AVAILABLE = True
            return pick_answer(row, lang)
        _RPC_AVAILABLE = True
        return None

    except Exception as e:
        payload = None
        try:
            payload = e.args[0]
        except Exception:
            payload = None

        msg = ""
        code = ""
        if isinstance(payload, dict):
            msg = str(payload.get("message", ""))
            code = str(payload.get("code", ""))
        else:
            msg = str(e)

        missing = ("PGRST202" in msg) or (code == "PGRST202") or ("Could not find the function" in msg) or ("schema cache" in msg)

        if missing:
            _RPC_AVAILABLE = False
            if not _RPC_MISSING_LOGGED:
                _RPC_MISSING_LOGGED = True
                logging.info("Supabase RPC %s not found; falling back to non-RPC matching.", fn_name)
            return None

        logging.warning("Supabase RPC %s failed (non-fatal): %s", fn_name, msg)
        return None

def library_get(question: str, lang: str = "en") -> Optional[str]:
    if not ENABLE_QA_LIBRARY:
        return None

    nq = normalize_question(question)
    if not nq:
        return None

    candidates = expand_queries(nq)

    try:
        # 1) exact match
        for c in candidates:
            res = (
                supabase.table("qa_library")
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
        ans_sim = _rpc_best_answer("qa_library_search", candidates[0], lang)
        if ans_sim:
            return ans_sim

        # 2) contains match (ILIKE) + scoring
        tokens = nq.split()

        SAFE_ACRONYMS = {"vat", "tin", "paye", "wht", "firs", "pit", "cit", "cgt"}
        keywords = [t for t in tokens if (len(t) >= 4) or (t in SAFE_ACRONYMS)]
        if not keywords:
            keywords = tokens

        keywords = keywords[:3]

        best_answer = None
        best_score = -1

        for kw in keywords:
            q = (
                supabase.table("qa_library")
                .select(f"{ANSWER_COLS},normalized_question,priority")
                .eq("enabled", True)
            )

            if kw in SAFE_ACRONYMS and len(kw) <= 4:
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
                score = (hits * 100) + (pri * 5) - (min(len(cand_q), 160) // 10)

                if score > best_score:
                    best_score = score
                    best_answer = pick_answer(r, lang)

        return best_answer

    except Exception:
        logging.exception("library_get failed")
        return None

def cache_get(question: str) -> Optional[str]:
    if not ENABLE_QA_CACHE:
        return None

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

        try:
            cid = row.get("id")
            use_count = safe_int(row.get("use_count"), 0) + 1
            if cid:
                supabase.table("qa_cache").update({
                    "use_count": use_count,
                    "last_used_at": iso(now_utc()),
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
# OpenAI AI Answer (text)
# ------------------------------------------------------------
def ai_answer_text(question: str, lang: str = "en") -> str:
    if not OPENAI_API_KEY:
        return "Service is temporarily unavailable. Please try again later."

    sys = (
        "You are Naija Hustle Tax Guide.\n"
        "Provide Nigeria-focused tax guidance that is clear, professional, and actionable.\n"
        "Write in Markdown with this structure:\n"
        "1) ### Direct Answer (2–6 short sentences)\n"
        "2) ### What to do next (3–6 bullet points)\n"
        "3) ### Documents to keep (bullets)\n"
        "4) ### Common mistakes (bullets)\n"
        "Keep it concise. Avoid legal overconfidence. If uncertain, say so and advise confirming with FIRS/State IRS or a qualified tax professional."
    )

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
            logging.warning("OpenAI error %s: %s", r.status_code, (r.text or "")[:200])
            return "Sorry — I couldn’t generate an answer right now. Please try again."
        data = r.json()
        msg = (((data.get("choices") or [])[0].get("message") or {}).get("content") or "").strip()
        return msg or "Sorry — I couldn’t generate an answer right now. Please try again."
    except Exception:
        logging.exception("ai_answer_text failed")
        return "Sorry — I couldn’t generate an answer right now. Please try again."

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
            logging.warning("Storage upload failed %s: %s", r.status_code, (r.text or "")[:200])
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
            logging.warning("OpenAI TTS error %s: %s", r.status_code, (r.text or "")[:200])
            return None
        return r.content
    except Exception:
        logging.exception("openai_tts failed")
        return None

def voice_cache_get(nq: str, provider: str, style: str) -> Optional[str]:
    try:
        res = (
            supabase.table("voice_cache")
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
                supabase.table("voice_cache").update({
                    "use_count": use_count,
                    "last_used_at": iso(now_utc()),
                }).eq("id", vid).execute()
        except Exception:
            pass
        return row.get("audio_url")
    except Exception:
        logging.exception("voice_cache_get failed")
        return None


def voice_cache_set(normalized_question: str, voice_provider: str, voice_style: str, audio_url: str) -> None:
    """Persist voice audio URL without relying on PostgREST upsert conflict targets.

    Supabase/PostgREST upsert with on_conflict requires a UNIQUE constraint. Some DB setups
    do not yet have that constraint, which causes a 42P10 error. This implementation uses:
      1) SELECT existing row (if any)
      2) UPDATE by id, else INSERT
    """
    try:
        existing = (
            supabase.table("voice_cache")
            .select("id,use_count")
            .eq("normalized_question", normalized_question)
            .eq("voice_provider", voice_provider)
            .eq("voice_style", voice_style)
            .limit(1)
            .execute()
        )
        rows = getattr(existing, "data", None) or []
        if rows:
            vid = rows[0].get("id")
            uc = int(rows[0].get("use_count") or 0) + 1
            supabase.table("voice_cache").update({
                "audio_url": audio_url,
                "use_count": uc,
                "last_used_at": iso(now_utc()),
            }).eq("id", vid).execute()
            return

        supabase.table("voice_cache").insert({
            "normalized_question": normalized_question,
            "voice_provider": voice_provider,
            "voice_style": voice_style,
            "audio_url": audio_url,
            "use_count": 1,
            "last_used_at": iso(now_utc()),
        }).execute()
    except Exception:
        logging.exception("voice_cache_set failed")
        return
def ensure_voice_for_text(nq: str, md_text: str, provider: str, style: str) -> Tuple[Optional[str], bool]:
    """
    Generate voice for an answer.
    Important: the answer is Markdown, so we strip formatting for TTS input.
    """
    cached_url = voice_cache_get(nq, provider, style)
    if cached_url:
        return cached_url, False

    tts_text = strip_markdown_for_tts(md_text)
    audio_bytes = openai_tts(tts_text, style) if provider == "openai" else None
    if not audio_bytes:
        return None, False

    key = hashlib.sha256(f"{provider}:{style}:{nq}".encode("utf-8")).hexdigest()[:24]
    obj_path = f"{provider}/{style}/{key}.mp3"
    url = supabase_storage_upload(obj_path, audio_bytes, "audio/mpeg")
    if not url:
        return None, False

    voice_cache_set(nq, provider, style, url)
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
        return "You’ve reached today’s free plan limit. Please try again tomorrow or subscribe via /pricing for higher access."
    return None

def can_use_ai(wa_phone: str) -> Tuple[bool, Optional[str]]:
    """Policy for using AI answers.

    For now, keep this simple and stable:
    - If subscription is active -> AI allowed
    - If not subscribed -> blocked with subscribe link
    """
    sub = get_user_subscription(wa_phone)
    status = (sub.get("status") or "").lower()
    expires_at = sub.get("expires_at")
    if status == "active" and expires_at:
        return True, None
    # free / not subscribed
    return False, f"To continue, please subscribe here: {PRICING_PATH}"
def _norm(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def _is_short_question(q: str) -> bool:
    return len(_norm(q).split()) <= 3

def _tin_who_policy(q: str) -> str:
    return (
        "### Direct Answer\n"
        "**TIN is not something you “pay”.** It is a **Tax Identification Number** you **register for**.\n\n"
        "**Who should get a TIN in Nigeria?**\n"
        "- **Individuals** earning taxable income (salary, business, freelance, contracts)\n"
        "- **Sole proprietors** and **partnerships** doing business\n"
        "- **Companies** registered with CAC (TIN is often issued alongside/after registration processes)\n"
        "- Anyone who needs to **file taxes**, open **business bank accounts**, bid for **contracts**, or do formal business transactions that require tax identity\n\n"
        "### What I need from you (to be specific)\n"
        "- Are you an **individual** or a **business/company**?\n"
        "- Which **state** are you operating from?\n\n"
        f"{DISCLAIMER}"
    )

def _answer_quality_gate(question: str, answer: str) -> bool:
    """
    Non-AI relevance check:
    - If question mentions 'tin', answer must mention 'tin' or 'tax identification'
    - If question asks 'who', answer should include 'individual'/'business'/'company' or similar
    """
    q = _norm(question)
    a = _norm(answer)

    if "tin" in q:
        if not ("tin" in a or "tax identification" in a):
            return False

    if q.startswith("who") or " who " in q:
        if not any(k in a for k in ["individual", "business", "company", "employer", "employee", "taxpayer"]):
            return False

    return True

def answer_engine_reply(phone: str, text: str, lang: str = "en") -> str:
    """
    Generic fallback engine (used by WhatsApp/Telegram router).
    Applies deterministic fixes + short-question guard + relevance gate.
    """
    q = (text or "").strip()
    nq = _norm(q)

    # 1) Strong deterministic fix for common issue
    if "tin" in nq and any(k in nq for k in ["who", "need", "needs", "should", "pay", "pays"]):
        return _tin_who_policy(q)

    # 2) If question is too short, request clarification (prevents bad guesses)
    if _is_short_question(q):
        return (
            "### Quick clarification\n"
            "To answer correctly, please tell me:\n"
            "- Are you asking as an **individual** or a **business**?\n"
            "- Which **state** are you in?\n"
            "- What is the transaction/income involved?\n\n"
            f"{DISCLAIMER}"
        )

    # 3) Use the core resolver (library/cache/AI)
    result = resolve_answer(
        wa_phone=normalize_phone(phone),
        question=q,
        mode="text",
        voice_provider="openai",
        voice_style="default",
        lang=lang or "en",
    )
    ans = result.get("answer_text") or ""

    # 4) Quality gate: if answer is not relevant, ask clarification instead
    if not _answer_quality_gate(q, ans):
        return (
            "### I need one quick detail\n"
            "I want to be accurate. Please clarify:\n"
            "- Are you asking as an **individual** or a **business/company**?\n"
            "- Which **state** are you operating from?\n\n"
            f"{DISCLAIMER}"
        )

    return ans

# ------------------------------------------------------------
# Core resolver
# ------------------------------------------------------------
def resolve_answer(
    wa_phone: str,
    question: str,
    mode: str,
    voice_provider: str,
    voice_style: str,
    lang: str = "en",
) -> Dict[str, Any]:
    wa_phone = normalize_phone(wa_phone)
    question = (question or "").strip()
    nq = normalize_question(question)

    msg = enforce_daily_total_limit_or_message(wa_phone)
    if msg:
        formatted = format_markdown_answer(question, msg)
        return {"ok": True, "answer_text": formatted, "audio_url": None, "credits_used": 0, "meta": {"source": "limit"}}

    # 1) library
    lib_ans = library_get(question, lang)
    if lib_ans:
        formatted = format_markdown_answer(question, lib_ans)
        daily_total_usage_inc(wa_phone, 1)
        ai_daily_usage_inc(wa_phone, total_inc=1, ai_inc=0)

        if mode == "voice":
            audio_url, generated_now = ensure_voice_for_text(nq, formatted, voice_provider, voice_style)
            credits_used = 0
            if generated_now:
                allowed, _, _ = can_use_ai(wa_phone, VOICE_CACHED_FIRST_GEN_COST)
                if not allowed:
                    return {"ok": True, "answer_text": formatted, "audio_url": None, "credits_used": 0, "meta": {"source": "library", "voice": "blocked"}}
                credits_used = VOICE_CACHED_FIRST_GEN_COST
                ledger_add(wa_phone, "tts_cached_gen", -credits_used, {"source": "library", "nq": nq})
            return {"ok": True, "answer_text": formatted, "audio_url": audio_url, "credits_used": credits_used, "meta": {"source": "library"}}

        return {"ok": True, "answer_text": formatted, "audio_url": None, "credits_used": 0, "meta": {"source": "library"}}

    # 2) cache
    cached = cache_get(question)
    if cached:
        formatted = format_markdown_answer(question, cached)
        daily_total_usage_inc(wa_phone, 1)
        ai_daily_usage_inc(wa_phone, total_inc=1, ai_inc=0)

        if mode == "voice":
            audio_url, generated_now = ensure_voice_for_text(nq, formatted, voice_provider, voice_style)
            credits_used = 0
            if generated_now:
                allowed, _, _ = can_use_ai(wa_phone, VOICE_CACHED_FIRST_GEN_COST)
                if not allowed:
                    return {"ok": True, "answer_text": formatted, "audio_url": None, "credits_used": 0, "meta": {"source": "cache", "voice": "blocked"}}
                credits_used = VOICE_CACHED_FIRST_GEN_COST
                ledger_add(wa_phone, "tts_cached_gen", -credits_used, {"source": "cache", "nq": nq})
            return {"ok": True, "answer_text": formatted, "audio_url": audio_url, "credits_used": credits_used, "meta": {"source": "cache"}}

        return {"ok": True, "answer_text": formatted, "audio_url": None, "credits_used": 0, "meta": {"source": "cache"}}

    # 3) AI fallback
    credits_needed = VOICE_AI_COST if mode == "voice" else TEXT_AI_COST
    allowed, reason, _ = can_use_ai(wa_phone, credits_needed)
    if not allowed:
        daily_total_usage_inc(wa_phone, 1)
        ai_daily_usage_inc(wa_phone, total_inc=1, ai_inc=0)
        msg = f"{reason}\n\nPlease subscribe to continue asking questions."
        formatted = format_markdown_answer(question, msg)
        return {"ok": True, "answer_text": formatted, "audio_url": None, "credits_used": 0, "meta": {"source": "ai_blocked"}}

    ans_raw = ai_answer_text(question, lang=lang)
    ans = format_markdown_answer(question, ans_raw)
    cache_set(question, ans)

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
    return jsonify({"ok": True, "service": "naija-tax-guide", "time_utc": iso(now_utc())})

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
    except Exception:
        logging.exception("ASK failed wa_phone=%s lang=%s mode=%s", wa_phone, lang, mode)
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
        logging.warning("Webhook reference not found in payments: %s", reference)
        return "ok", 200

    pay = rows[0]
    wa_phone = pay.get("wa_phone")
    plan = pay.get("plan")

    meta = data.get("metadata") or {}
    wa_phone = wa_phone or meta.get("wa_phone")
    plan = plan or meta.get("plan")

    if not wa_phone or not plan:
        logging.warning("Webhook missing wa_phone/plan for reference=%s", reference)
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
    logging.info("WA_VERIFY_HIT mode=%s token_len=%s has_challenge=%s", mode, len(token), bool(challenge))
    if mode == "subscribe" and token and WHATSAPP_VERIFY_TOKEN and token == WHATSAPP_VERIFY_TOKEN:
        return challenge, 200
    return "forbidden", 403

@app.post("/whatsapp/webhook")
def whatsapp_webhook_inbound():
    payload = request.get_json(silent=True) or {}
    logging.info("WA_WEBHOOK_HIT keys=%s", list(payload.keys()))

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
            result = resolve_answer(from_phone, text_body, "text", "openai", "default", "en")
            ok, info = send_whatsapp_text(from_phone, strip_markdown_for_tts(result.get("answer_text") or "OK"))
            logging.info("WA_REPLY ok=%s info=%s", ok, info)

    return "ok", 200

# ============================================================
# TELEGRAM INTEGRATION
# ============================================================
# Goal: Telegram Bot -> POST updates to our backend -> we reply with the same answer engine
#
# ENV required:
#   TELEGRAM_BOT_TOKEN=123456:ABC...
#   TELEGRAM_WEBHOOK_SECRET=some-long-random-string   (recommended)
#
# Webhook URL pattern:
#   https://YOUR_KOYEB_APP_URL/telegram/webhook/<TELEGRAM_WEBHOOK_SECRET>
#
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()

def tg_api_url(method: str) -> str:
    return f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/{method}"

def tg_send_message(chat_id: int, text: str, parse_mode: str = "Markdown") -> Tuple[bool, str]:
    if not TELEGRAM_BOT_TOKEN:
        return False, "TELEGRAM_BOT_TOKEN missing"
    payload = {
        "chat_id": chat_id,
        "text": (text or "")[:3800],
        "disable_web_page_preview": True,
    }
    # Telegram Markdown is picky; our content is Markdown-like.
    # If parse fails, Telegram will reject. So we default to plain text by not setting parse_mode.
    # You can enable parse_mode later once you're satisfied with formatting.
    try:
        r = requests.post(tg_api_url("sendMessage"), json=payload, timeout=20)
        if r.status_code >= 300:
            return False, f"sendMessage failed: {r.status_code} {r.text[:250]}"
        return True, "ok"
    except Exception as e:
        return False, f"sendMessage exception: {str(e)[:200]}"

def tg_send_audio(chat_id: int, audio_url: str, caption: str = "") -> Tuple[bool, str]:
    if not TELEGRAM_BOT_TOKEN:
        return False, "TELEGRAM_BOT_TOKEN missing"
    payload = {
        "chat_id": chat_id,
        "audio": audio_url,
        "caption": (caption or "")[:900],
    }
    try:
        r = requests.post(tg_api_url("sendAudio"), json=payload, timeout=30)
        if r.status_code >= 300:
            return False, f"sendAudio failed: {r.status_code} {r.text[:250]}"
        return True, "ok"
    except Exception as e:
        return False, f"sendAudio exception: {str(e)[:200]}"


@app.post("/telegram/webhook")
def telegram_webhook_no_secret():
    """
    Telegram webhook endpoint.

    If you set `secret_token` on Telegram setWebhook, Telegram will send
    header: X-Telegram-Bot-Api-Secret-Token. We verify it against TELEGRAM_WEBHOOK_SECRET.
    """
    if TELEGRAM_WEBHOOK_SECRET:
        hdr = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "") or request.headers.get("x-telegram-bot-api-secret-token", "")
        if not hmac.compare_digest(hdr.strip(), TELEGRAM_WEBHOOK_SECRET.strip()):
            return "unauthorized", 401

    update = request.get_json(silent=True) or {}
    try:
        handle_telegram_update(update)
    except Exception:
        logging.exception("Telegram webhook handler error")
    return "ok", 200


@app.post("/telegram/webhook/<secret>")
def telegram_webhook(secret: str):
    """
    Legacy/alternate webhook where secret is part of the URL path.
    """
    expected = (TELEGRAM_WEBHOOK_SECRET or "").strip()
    if expected and not hmac.compare_digest(secret.strip(), expected):
        return "unauthorized", 401

    update = request.get_json(silent=True) or {}
    try:
        handle_telegram_update(update)
    except Exception:
        logging.exception("Telegram webhook handler error")
    return "ok", 200


@app.get("/telegram/webhook-info")
def telegram_webhook_info():
    """
    Quick sanity endpoint: tells you whether the server sees TELEGRAM_WEBHOOK_SECRET
    (masked) and whether TELEGRAM_BOT_TOKEN is set.
    """
    return jsonify({
        "ok": True,
        "has_bot_token": bool(TELEGRAM_BOT_TOKEN),
        "has_webhook_secret": bool(TELEGRAM_WEBHOOK_SECRET),
        "webhook_secret_prefix": (TELEGRAM_WEBHOOK_SECRET or "")[:6] + "…" if TELEGRAM_WEBHOOK_SECRET else None,
        "telegram_short_mode": TELEGRAM_SHORT_MODE,
    })


def tg_plan_list_text() -> str:
    items = []
    for key, rule in PLAN_RULES.items():
        price = rule.get("price_ngn")
        if not price:
            continue
        items.append(f"- {key}: ₦{int(price):,} / {rule.get('duration_days', DEFAULT_PLAN_DAYS)} days")
    if not items:
        return "Plans are not configured yet."
    return "Available plans:\n" + "\n".join(items)


def tg_help_text() -> str:
    return (
        "Naija Tax Guide (Telegram)\n\n"
        "Commands:\n"
        "/start - welcome\n"
        "/help - this help\n"
        "/pricing - show plans\n"
        "/status - show your subscription expiry\n"
        "/subscribe <plan> <email> - get a Paystack payment link\n\n"
        "Or just type your tax question.\n"
        "Example:\n"
        "/subscribe basic you@example.com\n"
    )


def tg_parse_intent(text: str) -> Tuple[str, Dict[str, Any]]:
    t = (text or "").strip()
    if not t:
        return "empty", {}
    tl = t.lower()

    if tl.startswith("/start"):
        return "start", {}
    if tl.startswith("/help"):
        return "help", {}
    if tl.startswith("/pricing") or tl.startswith("/plans"):
        return "pricing", {}
    if tl.startswith("/status"):
        return "status", {}
    if tl.startswith("/subscribe"):
        # /subscribe <plan> <email>
        parts = t.split()
        plan = parts[1].strip().lower() if len(parts) >= 2 else ""
        email = parts[2].strip() if len(parts) >= 3 else ""
        return "subscribe", {"plan": plan, "email": email}

    return "ask", {"q": t}


def handle_telegram_update(update: Dict[str, Any]) -> None:
    """
    Main Telegram update handler (intent-based).
    """
    msg = update.get("message") or update.get("edited_message") or {}
    chat = msg.get("chat") or {}
    chat_id = int(chat.get("id") or 0)
    if not chat_id:
        return

    text = (msg.get("text") or "").strip()
    intent, data = tg_parse_intent(text)

    # Pseudo wa_phone for telegram users (shared with Supabase subscription table)
    wa_phone = f"tg:{chat_id}"

    if intent in ("start", "help"):
        tg_send_message(chat_id, tg_help_text())
        return

    if intent == "pricing":
        tg_send_message(chat_id, tg_plan_list_text())
        return

    if intent == "status":
        sub = get_user_subscription(wa_phone)
        if sub and sub.get("status") == "active":
            exp = sub.get("expires_at")
            tg_send_message(chat_id, f"Your plan is active.\nExpiry: {format_plan_expiry(exp)}")
        else:
            tg_send_message(chat_id, "You are not subscribed yet.\n\n" + tg_plan_list_text() + "\n\nUse:\n/subscribe <plan> <email>")
        return

    if intent == "subscribe":
        plan = (data.get("plan") or "").strip().lower()
        email = (data.get("email") or "").strip()

        if not plan or plan not in PLAN_RULES:
            tg_send_message(chat_id, "Please choose a valid plan.\n\n" + tg_plan_list_text() + "\n\nUse:\n/subscribe <plan> <email>")
            return
        if not email or "@" not in email:
            tg_send_message(chat_id, "Please include a valid email.\nExample:\n/subscribe basic you@example.com")
            return

        ok, auth_or_err, _ref = create_paystack_authorization_url(email=email, wa_phone=wa_phone, plan=plan)
        if not ok:
            tg_send_message(chat_id, f"Payment link error: {auth_or_err}")
            return

        tg_send_message(
            chat_id,
            "Payment link created.\n"
            "1) Open the link below and complete payment\n"
            "2) After payment, come back and send /status\n\n"
            f"{auth_or_err}"
        )
        return

    # Default: treat as question
    if intent == "ask":
        q = (data.get("q") or "").strip()
        if not q:
            tg_send_message(chat_id, "Please type a question.")
            return

        res = resolve_answer(wa_phone=wa_phone, question=q, mode="text", lang="en", voice_provider="none", voice_style="default")
        text_out = res.get("answer") or ""
        meta = res.get("meta") or {}

        # If AI is blocked (not subscribed or quota), add clear payment CTA for Telegram users
        if meta.get("source") == "ai_blocked":
            text_out = (
                text_out.strip()
                + "\n\n"
                + "To unlock full answers on Telegram:\n"
                + tg_plan_list_text()
                + "\n\nUse:\n/subscribe <plan> <email>"
            )

        tg_send_message(chat_id, text_out or "Sorry — I could not generate a reply.")
        return

def telegram_webhook_info():
    # Quick diagnostics endpoint (safe to keep)
    return jsonify({
        "ok": True,
        "has_bot_token": bool(TELEGRAM_BOT_TOKEN),
        "has_secret": bool(TELEGRAM_WEBHOOK_SECRET),
        "expected_path": f"/telegram/webhook/{TELEGRAM_WEBHOOK_SECRET}" if TELEGRAM_WEBHOOK_SECRET else "/telegram/webhook/<secret>",
    })

# ------------------------------------------------------------
# Local run (optional)
# ------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
