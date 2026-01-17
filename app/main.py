# app/main.py
import os
import json
import hmac
import hashlib
import logging
import uuid
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

# AI / OpenAI
AI_ENABLED = os.getenv("AI_ENABLED", "false").strip().lower() in ("1", "true", "yes", "on")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()  # safe default if you use OpenAI
# If you want to allow AI replies even for non-subscribers (NOT recommended for cost):
AI_ALLOW_FREE_USERS = os.getenv("AI_ALLOW_FREE_USERS", "false").strip().lower() in ("1", "true", "yes", "on")

# Public site base URL (optional but recommended)
APP_BASE_URL = os.getenv("APP_BASE_URL", "").strip()  # e.g. https://your-koyeb-service.koyeb.app
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "").strip()  # e.g. https://thecre8hub.com

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

def safe_trunc(s: str, n: int = 250) -> str:
    s = (s or "")
    return s[:n]

# ------------------------------------------------------------
# Subscription
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
        if status == "active" and expires_at:
            try:
                exp = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
                active = exp > now_utc()
            except Exception:
                # If parsing fails, treat as active to avoid blocking paid users
                active = True

        return {"exists": True, "active": active, "plan": plan, "status": status, "expires_at": expires_at}
    except Exception as e:
        logging.exception("get_subscription_status failed")
        return {
            "exists": False,
            "active": False,
            "plan": None,
            "status": "error",
            "expires_at": None,
            "error": str(e)[:200],
        }

def activate_user_subscription(wa_phone: str, plan: str) -> None:
    days = PLAN_RULES.get(plan, {}).get("days", 30)
    expires_at = iso(now_utc() + timedelta(days=days))
    supabase.table("user_subscriptions").upsert(
        {
            "wa_phone": normalize_phone(wa_phone),
            "plan": plan,
            "status": "active",
            "expires_at": expires_at,
            "updated_at": iso(now_utc()),
        },
        on_conflict="wa_phone",
    ).execute()

def upsert_pending_subscription(wa_phone: str, plan: str) -> None:
    supabase.table("user_subscriptions").upsert(
        {
            "wa_phone": normalize_phone(wa_phone),
            "plan": plan,
            "status": "pending",
            "expires_at": None,
            "updated_at": iso(now_utc()),
        },
        on_conflict="wa_phone",
    ).execute()

# ------------------------------------------------------------
# QA Cache
# ------------------------------------------------------------
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

        # best-effort update
        try:
            cid = row.get("id")
            use_count = int(row.get("use_count") or 0) + 1
            if cid:
                supabase.table("qa_cache").update(
                    {"use_count": use_count, "last_used_at": now_utc().isoformat()}
                ).eq("id", cid).execute()
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
        supabase.table("qa_cache").insert(
            {
                "normalized_question": nq,
                "answer": (answer or "").strip(),
                "tags": [],
                "use_count": 0,
                "last_used_at": now_utc().isoformat(),
                "created_at": now_utc().isoformat(),
            }
        ).execute()
    except Exception:
        # If you later enforce unique normalized_question, switch to upsert
        return

# ------------------------------------------------------------
# WhatsApp send (ROBUST)
# ------------------------------------------------------------
def wa_api_url(path: str) -> str:
    # Keep version consistent with your current setup
    return f"https://graph.facebook.com/v24.0{path}"

def chunk_text(text: str, max_len: int = 1400) -> List[str]:
    """
    WhatsApp rejects very long messages. We'll split into safe chunks.
    """
    text = (text or "").strip()
    if not text:
        return [""]

    chunks: List[str] = []
    i = 0
    while i < len(text):
        part = text[i:i + max_len]
        cut = max(part.rfind("\n"), part.rfind(" "))
        if cut > 200:
            part = part[:cut].rstrip()
            i += cut
        else:
            i += max_len
        part = part.strip()
        if part:
            chunks.append(part)
    return chunks if chunks else [""]

def send_whatsapp_text_one(to_wa_phone: str, text: str) -> Tuple[bool, str]:
    if not WHATSAPP_TOKEN or not WHATSAPP_PHONE_NUMBER_ID:
        msg = "WHATSAPP_TOKEN or WHATSAPP_PHONE_NUMBER_ID missing"
        logging.error(f"WA_SEND_FAIL {msg}")
        return False, msg

    to_wa_phone = normalize_phone(to_wa_phone)
    url = wa_api_url(f"/{WHATSAPP_PHONE_NUMBER_ID}/messages")
    headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}", "Content-Type": "application/json"}

    payload = {
        "messaging_product": "whatsapp",
        "to": to_wa_phone,
        "type": "text",
        "text": {"preview_url": False, "body": (text or "").strip()},
    }

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=25)
        if r.status_code >= 300:
            # THIS is what you need to see when “no reply” happens
            logging.error(f"WA_SEND_HTTP_ERROR status={r.status_code} body={safe_trunc(r.text, 800)}")
            return False, f"WhatsApp send failed: {r.status_code} {safe_trunc(r.text, 250)}"
        return True, "ok"
    except Exception as e:
        logging.exception("WA_SEND_EXCEPTION")
        return False, f"WhatsApp send exception: {str(e)[:200]}"

def wa_reply(to_wa_phone: str, text: str) -> Tuple[bool, str]:
    """
    Sends in chunks so long AI replies never fail silently.
    """
    parts = chunk_text(text, max_len=1400)
    for idx, part in enumerate(parts):
        ok, info = send_whatsapp_text_one(to_wa_phone, part)
        logging.info(f"WA_SEND_CHUNK idx={idx+1}/{len(parts)} ok={ok} info={info}")
        if not ok:
            return False, info
    return True, "ok"

# ------------------------------------------------------------
# Pricing / Help
# ------------------------------------------------------------
def format_plans_text() -> str:
    site = FRONTEND_BASE_URL or APP_BASE_URL or ""
    link_line = f"\n\nSubscribe here: {site}" if site else ""
    return (
        "Naija Tax Guide Plans:\n"
        "1) MONTHLY - ₦3,000\n"
        "2) QUARTERLY - ₦8,000\n"
        "3) YEARLY - ₦30,000\n\n"
        "Reply:\n"
        "SUBSCRIBE monthly\n"
        "SUBSCRIBE quarterly\n"
        "SUBSCRIBE yearly\n"
        f"{link_line}\n\n"
        "Or reply HELP to see commands."
    )

def format_help_text() -> str:
    return (
        "Commands you can send:\n"
        "HELP - show this menu\n"
        "PLANS - see subscription plans\n"
        "SUBSCRIBE monthly|quarterly|yearly - start a plan\n"
        "STATUS - check your subscription\n\n"
        "Or send any tax question directly."
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
        sub = get_subscription_status(from_phone)
        if sub.get("status") == "error":
            return "STATUS: Unable to read subscription right now. Please try again."
        if not sub.get("exists"):
            return "STATUS: No subscription found yet. Reply PLANS to see options."
        plan = (sub.get("plan") or "unknown").upper()
        status = (sub.get("status") or "unknown").upper()
        expires_at = sub.get("expires_at") or "-"
        active = "YES" if sub.get("active") else "NO"
        return f"STATUS:\nPlan: {plan}\nState: {status}\nActive: {active}\nExpires: {expires_at}"

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

        site = FRONTEND_BASE_URL or APP_BASE_URL or ""
        link_line = f"\n\nPay here: {site}" if site else ""
        return (
            f"SUBSCRIBE: {plan.upper()} selected.\n"
            "Next step: complete payment on the website."
            f"{link_line}\n\n"
            "If you already paid, reply STATUS in 1–2 minutes."
        )

    return None

# ------------------------------------------------------------
# AI (REAL) - Low cost / safe, with hard fallbacks
# ------------------------------------------------------------
def ai_answer(question: str) -> str:
    """
    Uses OpenAI if enabled. If it fails, returns a helpful fallback text.
    IMPORTANT: We keep the output concise to reduce WhatsApp length + cost.
    """
    q = (question or "").strip()
    if not q:
        return "Please send your tax question in one sentence."

    if not AI_ENABLED:
        return (
            "AI is currently disabled.\n\n"
            "Reply PLANS to subscribe, or ask again later."
        )

    if not OPENAI_API_KEY:
        logging.error("AI_ENABLED is true but OPENAI_API_KEY is missing")
        return (
            "AI is enabled but not configured correctly (missing API key).\n"
            "Please try again later."
        )

    # System prompt: short answers, practical, Nigeria context
    system = (
        "You are Naija Tax Guide. Answer Nigerian tax questions clearly and briefly. "
        "Use simple language, bullet points where helpful, and keep answers under ~1200 characters. "
        "If the question is unclear, ask 1 clarifying question."
    )

    # Try Responses API first (newer), fall back to Chat Completions if needed
    try:
        # 1) Responses API
        resp = requests.post(
            "https://api.openai.com/v1/responses",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": OPENAI_MODEL,
                "input": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": q},
                ],
                "max_output_tokens": 250,
            },
            timeout=35,
        )

        if resp.status_code < 300:
            data = resp.json()
            # Most common extraction
            text_out = ""
            try:
                # response.output_text exists in many responses
                text_out = (data.get("output_text") or "").strip()
            except Exception:
                text_out = ""

            if not text_out:
                # fallback extraction
                try:
                    out = data.get("output") or []
                    # Walk through possible content blocks
                    for item in out:
                        content = item.get("content") or []
                        for block in content:
                            if block.get("type") in ("output_text", "text"):
                                text_out += (block.get("text") or "")
                    text_out = (text_out or "").strip()
                except Exception:
                    text_out = ""

            if text_out:
                return text_out

            logging.error(f"OpenAI Responses API returned no text. body={safe_trunc(resp.text, 800)}")
        else:
            logging.error(f"OpenAI Responses API error status={resp.status_code} body={safe_trunc(resp.text, 800)}")

    except Exception:
        logging.exception("OpenAI Responses API exception")

    # 2) Chat Completions fallback
    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": OPENAI_MODEL,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": q},
                ],
                "max_tokens": 250,
                "temperature": 0.3,
            },
            timeout=35,
        )

        if resp.status_code < 300:
            data = resp.json()
            text_out = (((data.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
            if text_out:
                return text_out

            logging.error(f"Chat Completions returned no text. body={safe_trunc(resp.text, 800)}")
        else:
            logging.error(f"Chat Completions error status={resp.status_code} body={safe_trunc(resp.text, 800)}")

    except Exception:
        logging.exception("OpenAI Chat Completions exception")

    return (
        "Sorry — I couldn’t generate an answer right now.\n"
        "Please try again in 1 minute, or reply PLANS / STATUS."
    )

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
        "openai_model": OPENAI_MODEL,
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
# ASK (website + programmatic)
# ------------------------------------------------------------
@app.post("/ask")
def ask():
    body = request.get_json(silent=True) or {}
    wa_phone = normalize_phone(body.get("wa_phone") or "")
    question = (body.get("question") or "").strip()

    if not wa_phone:
        return jsonify({"ok": False, "error": "wa_phone is required"}), 400
    if not question:
        return jsonify({"ok": False, "error": "question is required"}), 400

    cached_answer = cache_get(question)
    if cached_answer:
        return jsonify({"ok": True, "cached": True, "answer": cached_answer, "meta": {"source": "cache"}})

    # For /ask, we do not enforce subscription strictly (depends on your business rules).
    # If you want strict gating, uncomment below:
    # sub = get_subscription_status(wa_phone)
    # if not sub.get("active"):
    #     return jsonify({"ok": True, "cached": False, "answer": format_plans_text(), "meta": {"source": "subscribe_gate"}})

    answer = ai_answer(question)
    cache_set(question, answer)
    return jsonify({"ok": True, "cached": False, "answer": answer, "meta": {"source": "ai"}})

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

    # log webhook hit
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

        logging.info(f"WA_MESSAGE from={from_phone} type={msg_type} body={safe_trunc(text_body, 160)}")

        if from_phone and text_body:
            # 1) Commands
            cmd_response = handle_inbound_command(from_phone, text_body)
            if cmd_response:
                ok, info = wa_reply(from_phone, cmd_response)
                logging.info(f"WA_REPLY_CMD ok={ok} info={info}")
                return "ok", 200

            # 2) Always try cache first (free)
            cached = None
            try:
                cached = cache_get(text_body)
            except Exception:
                cached = None

            if cached:
                ok, info = wa_reply(from_phone, cached)
                logging.info(f"WA_REPLY_CACHE ok={ok} info={info}")
                return "ok", 200

            # 3) Enforce subscription for AI (cost control)
            sub = get_subscription_status(from_phone)
            is_active = bool(sub.get("active"))

            if not is_active and not AI_ALLOW_FREE_USERS:
                msg_txt = (
                    "You are not subscribed yet.\n\n"
                    "Reply PLANS to see pricing and subscribe.\n"
                    "After payment, reply STATUS.\n\n"
                    "Tip: You can still use HELP / PLANS / STATUS anytime."
                )
                ok, info = wa_reply(from_phone, msg_txt)
                logging.info(f"WA_REPLY_SUB_GATE ok={ok} info={info}")
                return "ok", 200

            # 4) AI answer (paid users, or free allowed by env)
            try:
                answer = ai_answer(text_body)
                # cache it (even for paid users) to reduce future cost
                cache_set(text_body, answer)

                ok, info = wa_reply(from_phone, answer)
                logging.info(f"WA_REPLY_AI ok={ok} info={info}")

                # If WhatsApp send fails, we still return 200 so Meta doesn't retry forever
                return "ok", 200

            except Exception:
                logging.exception("Inbound AI handling failed")
                wa_reply(from_phone, "Sorry — system error. Please try again.")
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
