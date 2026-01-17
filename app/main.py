# app/main.py
import os
import json
import hmac
import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Dict, Tuple

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

# Feature flags
ENABLE_AI_REPLIES = os.getenv("ENABLE_AI_REPLIES", "true").strip().lower() in ("1", "true", "yes", "on")

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
    """
    Matches your Supabase qa_cache schema: normalized_question text
    Keep simple and stable.
    """
    return " ".join((q or "").strip().lower().split())

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
        plan = (row.get("plan") or None)

        active = False
        if status == "active" and expires_at:
            try:
                exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                active = exp > now_utc()
            except Exception:
                active = True
        return {"exists": True, "active": active, "plan": plan, "status": status, "expires_at": expires_at}
    except Exception as e:
        logging.exception("get_subscription_status failed")
        return {"exists": False, "active": False, "plan": None, "status": "error", "expires_at": None, "error": str(e)[:200]}

def activate_user_subscription(wa_phone: str, plan: str) -> None:
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
    supabase.table("user_subscriptions").upsert({
        "wa_phone": normalize_phone(wa_phone),
        "plan": plan,
        "status": "pending",
        "expires_at": None,
        "updated_at": iso(now_utc())
    }, on_conflict="wa_phone").execute()

# ------------------------------------------------------------
# QA Cache (matches your actual table schema)
# Columns:
# id uuid, normalized_question text, answer text, tags array,
# use_count integer, last_used_at timestamptz, created_at timestamptz
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
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return None

        row = rows[0]
        ans = row.get("answer") or ""

        # update usage stats (best effort)
        try:
            use_count = int(row.get("use_count") or 0) + 1
            supabase.table("qa_cache").update({
                "use_count": use_count,
                "last_used_at": iso(now_utc()),
            }).eq("id", row["id"]).execute()
        except Exception:
            pass

        return ans.strip() if ans else None
    except Exception:
        logging.exception("cache_get failed")
        return None

def cache_set(question: str, answer: str) -> None:
    nq = normalize_question(question)
    if not nq or not (answer or "").strip():
        return

    # We do insert-or-update without relying on ON CONFLICT,
    # because you may not have a unique constraint on normalized_question.
    try:
        existing = (
            supabase.table("qa_cache")
            .select("id,use_count")
            .eq("normalized_question", nq)
            .limit(1)
            .execute()
        )
        rows = existing.data or []
        if rows:
            row = rows[0]
            use_count = int(row.get("use_count") or 0)
            supabase.table("qa_cache").update({
                "answer": answer.strip(),
                "use_count": use_count,
                "last_used_at": iso(now_utc()),
            }).eq("id", row["id"]).execute()
            return

        supabase.table("qa_cache").insert({
            "normalized_question": nq,
            "answer": answer.strip(),
            "tags": [],
            "use_count": 0,
            "last_used_at": None,
            "created_at": iso(now_utc()),
        }).execute()
    except Exception:
        logging.exception("cache_set failed")
        return

# ------------------------------------------------------------
# AI stub (replace later)
# ------------------------------------------------------------
def ai_answer(question: str) -> str:
    return (
        "AI replies are enabled, but OpenAI is not connected yet.\n\n"
        f"Your question was:\n{question}"
    )

# ------------------------------------------------------------
# Health / Debug
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})

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
# ASK (used by website AND WhatsApp inbound)
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

    cached = cache_get(question)
    if cached:
        return jsonify({"ok": True, "cached": True, "answer": cached, "meta": {"source": "cache"}})

    if not ENABLE_AI_REPLIES:
        return jsonify({"ok": True, "cached": False, "answer": "AI replies are currently disabled.", "meta": {"source": "disabled"}})

    answer = ai_answer(question)
    cache_set(question, answer)
    return jsonify({"ok": True, "cached": False, "answer": answer, "meta": {"source": "ai_stub"}})

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
        upsert_pending_subscription(wa_phone, plan)
    except Exception:
        pass

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
        "1) MONTHLY - ₦3,000\n"
        "2) QUARTERLY - ₦8,000\n"
        "3) YEARLY - ₦30,000\n\n"
        "Reply:\n"
        "SUBSCRIBE monthly\n"
        "SUBSCRIBE quarterly\n"
        "SUBSCRIBE yearly\n\n"
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

        return (
            f"SUBSCRIBE: {plan.upper()} selected.\n"
            "Next step: complete payment on the website.\n"
            "If you already paid, reply STATUS in 1–2 minutes."
        )

    return None

# ------------------------------------------------------------
# WhatsApp Webhook (Meta verification + inbound messages)
# ------------------------------------------------------------
@app.get("/whatsapp/webhook")
def whatsapp_webhook_verify():
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    if mode == "subscribe" and token and WHATSAPP_VERIFY_TOKEN and token == WHATSAPP_VERIFY_TOKEN:
        logging.info("WH_VERIFY: success")
        return challenge, 200

    logging.warning(f"WH_VERIFY: forbidden mode={mode} token_match={token == WHATSAPP_VERIFY_TOKEN}")
    return "forbidden", 403

@app.post("/whatsapp/webhook")
def whatsapp_webhook_inbound():
    # This log line is the key: if Meta hits you, you WILL see it in Koyeb logs.
    logging.info("WH_INBOUND: received POST /whatsapp/webhook")

    payload = request.get_json(silent=True) or {}
    try:
        entry = (payload.get("entry") or [])[0]
        change = (entry.get("changes") or [])[0]
        value = change.get("value") or {}
    except Exception:
        logging.warning("WH_INBOUND: payload shape unexpected (no entry/changes/value)")
        return "ok", 200

    messages = value.get("messages") or []
    if not messages:
        # statuses, etc.
        logging.info("WH_INBOUND: no messages in payload (likely status event)")
        return "ok", 200

    # process ALL messages
    for msg in messages:
        from_phone = normalize_phone(msg.get("from") or "")
        msg_type = msg.get("type") or ""
        text_body = ""

        if msg_type == "text":
            text_body = ((msg.get("text") or {}).get("body") or "").strip()

        logging.info(f"WH_INBOUND: from={from_phone} type={msg_type} text_len={len(text_body)}")

        if not from_phone or not text_body:
            continue

        # 1) Commands
        cmd = handle_inbound_command(from_phone, text_body)
        if cmd:
            ok, detail = send_whatsapp_text(from_phone, cmd)
            logging.info(f"WH_REPLY: command ok={ok} detail={detail}")
            continue

        # 2) Normal question
        cached = cache_get(text_body)
        if cached:
            ok, detail = send_whatsapp_text(from_phone, cached)
            logging.info(f"WH_REPLY: cache ok={ok} detail={detail}")
            continue

        if not ENABLE_AI_REPLIES:
            ok, detail = send_whatsapp_text(from_phone, "AI replies are currently disabled.")
            logging.info(f"WH_REPLY: disabled ok={ok} detail={detail}")
            continue

        answer = ai_answer(text_body)
        cache_set(text_body, answer)
        ok, detail = send_whatsapp_text(from_phone, answer)
        logging.info(f"WH_REPLY: ai_stub ok={ok} detail={detail}")

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
