import os
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple, List

import requests
from flask import Flask, request, jsonify
from supabase import create_client

# ------------------------------------------------------------
# App / Env
# ------------------------------------------------------------
app = Flask(__name__)

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")  # optional for now

SERVICE_NAME = os.getenv("SERVICE_NAME", "naija-tax-guide-api")
DEFAULT_SESSION_TTL_HOURS = int(os.getenv("SESSION_TTL_HOURS", "24"))
OUTBOUND_BATCH_SIZE = int(os.getenv("OUTBOUND_BATCH_SIZE", "20"))

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY")
if not WHATSAPP_TOKEN or not WHATSAPP_PHONE_NUMBER_ID or not WHATSAPP_VERIFY_TOKEN:
    raise RuntimeError("Missing WHATSAPP_TOKEN or WHATSAPP_PHONE_NUMBER_ID or WHATSAPP_VERIFY_TOKEN")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

WA_MESSAGES_URL = f"https://graph.facebook.com/v21.0/{WHATSAPP_PHONE_NUMBER_ID}/messages"

# Reuse HTTP connection (faster + more stable)
_http = requests.Session()


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat()


def safe_text(s: Any) -> str:
    return (s or "").strip()


def to_number(s: str) -> Optional[float]:
    try:
        s = safe_text(s).replace(",", "")
        if s == "":
            return None
        return float(s)
    except Exception:
        return None


def send_reply(wa_phone: str, text: str) -> None:
    payload = {
        "messaging_product": "whatsapp",
        "to": wa_phone,
        "type": "text",
        "text": {"body": text},
    }
    headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}", "Content-Type": "application/json"}
    try:
        r = _http.post(WA_MESSAGES_URL, headers=headers, json=payload, timeout=30)
        # Do not crash the worker if WA fails
        if r.status_code >= 400:
            # Optional: you can log r.text into DB later
            pass
    except Exception:
        pass


def log_event(wa_phone: str, event: str, meta: Optional[Dict[str, Any]] = None) -> None:
    try:
        supabase.table("events").insert({
            "wa_phone": wa_phone,
            "event": event,
            "meta": meta or {}
        }).execute()
    except Exception:
        pass


# ------------------------------------------------------------
# USERS + SUBSCRIPTIONS
# ------------------------------------------------------------
def upsert_user_profile(wa_phone: str) -> None:
    try:
        supabase.table("users").upsert({
            "wa_phone": wa_phone,
            "last_seen_at": iso(now_utc()),
            "updated_at": iso(now_utc())
        }, on_conflict="wa_phone").execute()
    except Exception:
        pass


def get_user_plan(wa_phone: str) -> str:
    try:
        res = supabase.table("user_subscriptions") \
            .select("plan, status, expires_at") \
            .eq("wa_phone", wa_phone).limit(1).execute()
        if not res.data:
            return "free"

        row = res.data[0]
        plan = (row.get("plan") or "free").lower()
        status = (row.get("status") or "active").lower()
        expires_at = row.get("expires_at")

        if status != "active":
            return "free"

        if expires_at:
            try:
                exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                if exp < now_utc():
                    return "free"
            except Exception:
                pass

        return plan
    except Exception:
        return "free"


# ------------------------------------------------------------
# BILLING GUARD (keep in app.py for now; move later)
# ------------------------------------------------------------
def can_use_flow(user_plan: str, flow_key: str) -> bool:
    """
    MVP: allow these flows on free.
    Later: restrict advanced flows to paid plans.
    """
    flow_key = (flow_key or "").lower()
    user_plan = (user_plan or "free").lower()

    FREE_ALLOWED = {"menu", "vat", "hustler_onboarding", "paye", "guide"}
    if user_plan == "free":
        return flow_key in FREE_ALLOWED
    return True


# ------------------------------------------------------------
# FLOW SESSIONS (matches your existing schema)
# - status: active | expired | cancelled | switched_flow | restarted
# ------------------------------------------------------------
def get_active_session(wa_phone: str) -> Optional[Dict[str, Any]]:
    try:
        res = supabase.table("flow_sessions") \
            .select("*") \
            .eq("wa_phone", wa_phone) \
            .eq("status", "active") \
            .order("updated_at", desc=True) \
            .limit(1).execute()
        return res.data[0] if res.data else None
    except Exception:
        return None


def close_active_session(wa_phone: str, reason: str = "closed") -> None:
    try:
        supabase.table("flow_sessions") \
            .update({"status": reason, "updated_at": iso(now_utc())}) \
            .eq("wa_phone", wa_phone) \
            .eq("status", "active") \
            .execute()
    except Exception:
        pass


def create_session(wa_phone: str, flow_key: str) -> Dict[str, Any]:
    expires_at = iso(now_utc() + timedelta(hours=DEFAULT_SESSION_TTL_HOURS))
    row = {
        "wa_phone": wa_phone,
        "flow_key": flow_key,
        "status": "active",
        "current_step": "START",
        "step_index": 1,
        "context": {},
        "meta": {},
        "last_inbound_at": iso(now_utc()),
        "expires_at": expires_at,
        "updated_at": iso(now_utc()),
    }
    res = supabase.table("flow_sessions").insert(row).execute()
    return res.data[0] if res.data else row


def update_session(session_id: Any, patch: Dict[str, Any]) -> None:
    patch["updated_at"] = iso(now_utc())
    supabase.table("flow_sessions").update(patch).eq("id", session_id).execute()


def session_expired(session: Dict[str, Any]) -> bool:
    exp = session.get("expires_at")
    if not exp:
        return False
    try:
        dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        return dt < now_utc()
    except Exception:
        return False


# ------------------------------------------------------------
# COMMANDS / MENU
# ------------------------------------------------------------
def handle_command(message_text: str) -> Optional[Dict[str, Any]]:
    cmd = safe_text(message_text).lower()

    if cmd in ["menu", "help", "start"]:
        return {
            "reply": (
                "📌 *Naija Hustle Tax Guide*\n\n"
                "Reply any option:\n"
                "• VAT – VAT calculator\n"
                "• PAYE – PAYE estimator\n"
                "• BUSINESS – Hustler onboarding\n"
                "• GUIDE – Quick tax guides\n\n"
                "Commands:\n"
                "• restart – start over\n"
                "• cancel – end session\n"
                "• upgrade – paid plans (foundation)"
            )
        }

    if cmd == "restart":
        return {"action": "restart"}

    if cmd == "cancel":
        return {"action": "cancel"}

    if cmd == "upgrade":
        return {"action": "upgrade"}

    return None


def detect_flow_start(message_text: str) -> Optional[str]:
    t = safe_text(message_text).lower()
    if t in ["vat", "vat calculator"]:
        return "vat"
    if t in ["business", "hustle", "hustler", "hustler onboarding"]:
        return "hustler_onboarding"
    if t in ["paye", "salary", "salary tax"]:
        return "paye"
    if t in ["guide", "guides", "tax guide", "tax guides"]:
        return "guide"
    return None


# ------------------------------------------------------------
# BLOCK 1: PAYE CALCULATOR FLOW
# ------------------------------------------------------------
def fetch_paye_brackets() -> List[Dict[str, Any]]:
    try:
        res = supabase.table("paye_brackets") \
            .select("band_min, band_max, rate, sort_order") \
            .eq("country_code", "NG") \
            .eq("period", "monthly") \
            .order("sort_order", desc=False) \
            .execute()
        return res.data or []
    except Exception:
        return []


def compute_progressive_tax(taxable: float, brackets: List[Dict[str, Any]]) -> float:
    tax = 0.0
    for b in brackets:
        band_min = float(b["band_min"])
        band_max = b.get("band_max")
        rate = float(b["rate"])

        if taxable <= band_min:
            continue

        upper = float(band_max) if band_max is not None else None
        if upper is None:
            band_amount = max(0.0, taxable - band_min)
        else:
            band_amount = max(0.0, min(taxable, upper) - band_min)

        tax += band_amount * rate

    return max(0.0, tax)


def paye_flow_reply(session: Dict[str, Any], message_text: str) -> Tuple[str, Dict[str, Any]]:
    ctx = session.get("context") or {}
    step = session.get("current_step") or "START"
    t = safe_text(message_text)

    if step in ["START", "PAYE_ASK_GROSS"]:
        patch = {"current_step": "PAYE_ASK_GROSS", "step_index": 1}
        reply = (
            "✅ *PAYE Estimator (Monthly)*\n\n"
            "Enter your *monthly gross salary* (₦).\n"
            "Example: 450000"
        )
        return reply, patch

    if step == "PAYE_ASK_GROSS":
        gross = to_number(t)
        if gross is None or gross <= 0:
            return "❌ Enter a valid gross salary amount. Example: 450000", {}
        ctx["gross"] = gross
        patch = {"current_step": "PAYE_ASK_PENSION", "step_index": 2, "context": ctx}
        return (
            f"Gross recorded: ₦{gross:,.2f}\n\n"
            "Enter your *pension contribution %*.\n"
            "Example: 8\n"
            "If none, reply 0.",
            patch
        )

    if step == "PAYE_ASK_PENSION":
        pct = to_number(t)
        if pct is None or pct < 0 or pct > 50:
            return "❌ Enter a valid pension % (0 to 50). Example: 8", {}
        ctx["pension_pct"] = pct
        patch = {"current_step": "PAYE_ASK_OTHER_DED", "step_index": 3, "context": ctx}
        return (
            "Enter *other monthly tax-deductible items* (₦).\n"
            "Example: NHF, NHIS, approved deductions.\n"
            "If none, reply 0.",
            patch
        )

    if step == "PAYE_ASK_OTHER_DED":
        other = to_number(t)
        if other is None or other < 0:
            return "❌ Enter a valid amount. Example: 0 or 25000", {}

        gross = float(ctx.get("gross", 0))
        pension_pct = float(ctx.get("pension_pct", 0))
        pension_amt = gross * (pension_pct / 100.0)

        # CRA (config later)
        cra_monthly = 0.0
        cra_pct = float(os.getenv("CRA_PCT", "0"))
        cra_fixed_monthly = float(os.getenv("CRA_FIXED_MONTHLY", "0"))
        if cra_pct > 0:
            cra_monthly = gross * (cra_pct / 100.0) + cra_fixed_monthly

        taxable = max(0.0, gross - pension_amt - float(other) - cra_monthly)

        brackets = fetch_paye_brackets()
        tax = compute_progressive_tax(taxable, brackets) if brackets else 0.0

        ctx.update({
            "other_deductions": float(other),
            "pension_amount": pension_amt,
            "cra_monthly": cra_monthly,
            "taxable_income": taxable,
            "estimated_paye": tax
        })

        patch = {"current_step": "PAYE_SHOW", "step_index": 4, "context": ctx}

        reply = (
            "📊 *PAYE Estimate (Monthly)*\n\n"
            f"• Gross: ₦{gross:,.2f}\n"
            f"• Pension ({pension_pct}%): ₦{pension_amt:,.2f}\n"
            f"• Other deductible: ₦{float(other):,.2f}\n"
            f"• CRA (config): ₦{cra_monthly:,.2f}\n\n"
            f"• Taxable: ₦{taxable:,.2f}\n"
            f"✅ *Estimated PAYE:* ₦{tax:,.2f}\n\n"
            "Type *menu* for options or *restart* to calculate again."
        )
        return reply, patch

    return "Type *menu* to start.", {"current_step": "START", "step_index": 1}


# ------------------------------------------------------------
# VAT FLOW
# ------------------------------------------------------------
def vat_flow_reply(session: Dict[str, Any], message_text: str) -> Tuple[str, Dict[str, Any]]:
    ctx = session.get("context") or {}
    step = session.get("current_step") or "START"
    t = safe_text(message_text)

    if step in ["START", "VAT_ASK_SALES"]:
        patch = {"current_step": "VAT_ASK_SALES", "step_index": 1}
        return (
            "✅ *VAT Calculator (Nigeria)*\n\n"
            "Enter your *total sales/turnover amount* (₦).\nExample: 1500000",
            patch
        )

    if step == "VAT_ASK_SALES":
        sales = to_number(t)
        if sales is None or sales < 0:
            return "❌ Enter a valid sales amount. Example: 1500000", {}
        ctx["sales"] = sales
        patch = {"current_step": "VAT_ASK_INPUT", "step_index": 2, "context": ctx}
        return (
            f"Sales recorded: ₦{sales:,.2f}\n\n"
            "Now enter your *input VAT* (₦). If none, reply 0.",
            patch
        )

    if step == "VAT_ASK_INPUT":
        input_vat = to_number(t)
        if input_vat is None or input_vat < 0:
            return "❌ Enter a valid input VAT amount. Example: 0 or 25000", {}
        sales = float(ctx.get("sales", 0))
        vat_rate = float(os.getenv("VAT_RATE", "0.075"))
        output_vat = sales * vat_rate
        net = output_vat - float(input_vat)

        patch = {"current_step": "VAT_SHOW", "step_index": 3, "context": {
            **ctx,
            "input_vat": float(input_vat),
            "output_vat": output_vat,
            "net_vat": net
        }}

        verdict = f"✅ *VAT payable:* ₦{net:,.2f}" if net >= 0 else f"✅ *VAT credit:* ₦{abs(net):,.2f}"

        reply = (
            "📊 *VAT Summary*\n\n"
            f"• Sales: ₦{sales:,.2f}\n"
            f"• Output VAT: ₦{output_vat:,.2f}\n"
            f"• Input VAT: ₦{float(input_vat):,.2f}\n\n"
            f"{verdict}\n\n"
            "Type *menu* for more options."
        )
        return reply, patch

    return "Type *menu* to start.", {"current_step": "START", "step_index": 1}


# ------------------------------------------------------------
# BLOCK 2: BUSINESS + GUIDE
# ------------------------------------------------------------
def save_business_profile(wa_phone: str, patch: Dict[str, Any]) -> None:
    data = {"wa_phone": wa_phone, **patch, "updated_at": iso(now_utc())}
    supabase.table("business_profiles").upsert(data, on_conflict="wa_phone").execute()


def hustle_onboarding_reply(session: Dict[str, Any], message_text: str) -> Tuple[str, Dict[str, Any]]:
    ctx = session.get("context") or {}
    step = session.get("current_step") or "START"
    t = safe_text(message_text)

    if step in ["START", "HB_ASK_TYPE"]:
        patch = {"current_step": "HB_ASK_TYPE", "step_index": 1}
        return (
            "✅ *Hustler Onboarding*\n\n"
            "What do you do?\nExample: POS agent / Fashion / Food / Freelancer",
            patch
        )

    if step == "HB_ASK_TYPE":
        if len(t) < 2:
            return "❌ Please reply with a short business type. Example: POS agent", {}
        ctx["business_type"] = t
        patch = {"current_step": "HB_ASK_STATE", "step_index": 2, "context": ctx}
        return "Which state are you operating from? Example: Lagos", patch

    if step == "HB_ASK_STATE":
        ctx["state"] = t
        patch = {"current_step": "HB_ASK_REGISTERED", "step_index": 3, "context": ctx}
        return "Are you registered with CAC? Reply YES or NO.", patch

    if step == "HB_ASK_REGISTERED":
        yn = t.lower()
        if yn not in ["yes", "no", "y", "n"]:
            return "❌ Reply YES or NO.", {}
        ctx["registered"] = yn in ["yes", "y"]
        patch = {"current_step": "HB_DONE", "step_index": 4, "context": ctx}

        try:
            save_business_profile(session["wa_phone"], {
                "business_type": ctx.get("business_type"),
                "state": ctx.get("state"),
                "registered": bool(ctx.get("registered"))
            })
        except Exception:
            pass

        reply = (
            "✅ Onboarding saved.\n\n"
            f"• Business: {ctx.get('business_type')}\n"
            f"• State: {ctx.get('state')}\n"
            f"• CAC Registered: {'Yes' if ctx.get('registered') else 'No'}\n\n"
            "Type *GUIDE* for quick guides or *menu*."
        )
        return reply, patch

    return "Type *menu* to start.", {"current_step": "START", "step_index": 1}


def guide_flow_reply(session: Dict[str, Any], message_text: str) -> Tuple[str, Dict[str, Any]]:
    step = session.get("current_step") or "START"
    t = safe_text(message_text).lower()

    if step in ["START", "G_ASK_TOPIC"]:
        patch = {"current_step": "G_ASK_TOPIC", "step_index": 1}
        return (
            "📚 *Quick Guides*\n\n"
            "Reply with a topic:\n"
            "• VAT\n"
            "• PAYE\n"
            "• BUSINESS\n\n"
            "Or type *menu*.",
            patch
        )

    topic_map = {"vat": "vat_overview", "paye": "paye_overview", "business": "sme_basics"}
    if step == "G_ASK_TOPIC":
        if t not in topic_map:
            return "❌ Reply VAT, PAYE, or BUSINESS.", {}
        guide_key = topic_map[t]
        try:
            res = supabase.table("guides").select("title, body").eq("guide_key", guide_key).limit(1).execute()
            if not res.data:
                return "Guide not found yet. Type *menu*.", {}
            g = res.data[0]
            patch = {"current_step": "G_DONE", "step_index": 2}
            return f"📌 *{g['title']}*\n\n{g['body']}\n\nType *menu*.", patch
        except Exception:
            return "Guide error. Type *menu*.", {}

    return "Type *menu*.", {"current_step": "START", "step_index": 1}


# ------------------------------------------------------------
# BLOCK 3: REMINDERS + OUTBOUND QUEUE
# ------------------------------------------------------------
@app.get("/tasks/expire_sessions")
def expire_sessions():
    try:
        supabase.table("flow_sessions") \
            .update({"status": "expired", "updated_at": iso(now_utc())}) \
            .eq("status", "active") \
            .lt("expires_at", iso(now_utc())) \
            .execute()

        cutoff = iso(now_utc() - timedelta(hours=DEFAULT_SESSION_TTL_HOURS))
        supabase.table("flow_sessions") \
            .update({"status": "expired", "updated_at": iso(now_utc())}) \
            .eq("status", "active") \
            .lt("last_inbound_at", cutoff) \
            .execute()

        return jsonify({"status": "ok", "task": "expire_sessions"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@app.get("/tasks/queue_reminders")
def queue_reminders():
    try:
        hours = int(request.args.get("hours", "24"))
        inactive_since = iso(now_utc() - timedelta(hours=hours))
        recent_cutoff = iso(now_utc() - timedelta(hours=24))

        users = supabase.table("users") \
            .select("wa_phone, last_seen_at") \
            .lt("last_seen_at", inactive_since) \
            .limit(200) \
            .execute().data or []

        queued = 0
        for u in users:
            phone = u["wa_phone"]

            recent = supabase.table("outbound_queue") \
                .select("id") \
                .eq("wa_phone", phone) \
                .eq("status", "queued") \
                .gt("created_at", recent_cutoff) \
                .limit(1).execute().data

            if recent:
                continue

            msg = (
                "⏳ Quick reminder: you can continue anytime.\n\n"
                "Type:\n"
                "• VAT (calculator)\n"
                "• PAYE (estimator)\n"
                "• BUSINESS (onboarding)\n"
                "• GUIDE (tips)\n\n"
                "Reply *menu* to see options."
            )

            supabase.table("outbound_queue").insert({
                "wa_phone": phone,
                "message": msg,
                "status": "queued",
                "scheduled_for": iso(now_utc()),
                "meta": {"reason": "inactivity_reminder"}
            }).execute()
            queued += 1

        return jsonify({"status": "ok", "queued": queued})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@app.get("/tasks/dispatch_outbound")
def dispatch_outbound():
    try:
        batch = supabase.table("outbound_queue") \
            .select("*") \
            .eq("status", "queued") \
            .lte("scheduled_for", iso(now_utc())) \
            .order("scheduled_for", desc=False) \
            .limit(OUTBOUND_BATCH_SIZE) \
            .execute().data or []

        sent = 0
        failed = 0

        for row in batch:
            try:
                send_reply(row["wa_phone"], row["message"])
                supabase.table("outbound_queue").update({
                    "status": "sent",
                    "sent_at": iso(now_utc()),
                    "updated_at": iso(now_utc())
                }).eq("id", row["id"]).execute()
                sent += 1
            except Exception as e:
                supabase.table("outbound_queue").update({
                    "status": "failed",
                    "fail_reason": str(e),
                    "updated_at": iso(now_utc())
                }).eq("id", row["id"]).execute()
                failed += 1

        return jsonify({"status": "ok", "sent": sent, "failed": failed})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


# ------------------------------------------------------------
# BLOCK 4: UPGRADE + PAYSTACK FOUNDATION
# ------------------------------------------------------------
PLAN_PRICES = {
    "basic": 200000,  # kobo => ₦2,000 placeholder
    "pro":   500000,  # ₦5,000 placeholder
}


def upgrade_message() -> str:
    return (
        "💳 *Upgrade Plans* (foundation)\n\n"
        "Reply:\n"
        "• UPGRADE BASIC\n"
        "• UPGRADE PRO\n\n"
        "BASIC: ₦2,000/month (placeholder)\n"
        "PRO: ₦5,000/month (placeholder)\n\n"
        "After payment, your plan activates automatically."
    )


def create_payment_record(wa_phone: str, plan: str) -> Dict[str, Any]:
    plan = plan.lower()
    amount_kobo = PLAN_PRICES.get(plan)
    if amount_kobo is None:
        raise ValueError("invalid_plan")

    reference = f"local_{wa_phone}_{int(now_utc().timestamp())}_{plan}"

    res = supabase.table("payments").insert({
        "wa_phone": wa_phone,
        "provider": "paystack",
        "reference": reference,
        "plan": plan,
        "amount_kobo": int(amount_kobo),
        "currency": "NGN",
        "status": "initiated",
        "meta": {"mode": "foundation"}
    }).execute()

    return res.data[0] if res.data else {"reference": reference, "plan": plan, "amount_kobo": amount_kobo}


@app.post("/paystack/initialize")
def paystack_initialize():
    data = request.get_json(silent=True) or {}
    wa_phone = safe_text(data.get("wa_phone"))
    plan = safe_text(data.get("plan")).lower()

    if not wa_phone or plan not in PLAN_PRICES:
        return jsonify({"status": "error", "error": "wa_phone and valid plan required"}), 400

    try:
        payment = create_payment_record(wa_phone, plan)
        return jsonify({
            "status": "ok",
            "reference": payment["reference"],
            "plan": plan,
            "amount_kobo": payment["amount_kobo"],
            "message": "Foundation created. Wire Paystack later."
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@app.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if PAYSTACK_SECRET_KEY:
        expected = hmac.new(PAYSTACK_SECRET_KEY.encode("utf-8"), raw, hashlib.sha512).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return "invalid signature", 401

    # For now: ACK only
    return "ok", 200


# ------------------------------------------------------------
# ROUTER
# ------------------------------------------------------------
def route_flow(session: Dict[str, Any], message_text: str) -> Tuple[str, Dict[str, Any]]:
    fk = (session.get("flow_key") or "").lower()
    if fk == "vat":
        return vat_flow_reply(session, message_text)
    if fk == "paye":
        return paye_flow_reply(session, message_text)
    if fk == "hustler_onboarding":
        return hustle_onboarding_reply(session, message_text)
    if fk == "guide":
        return guide_flow_reply(session, message_text)
    return ("Type *menu* to start.", {})


# ------------------------------------------------------------
# HEALTH / ROOT
# ------------------------------------------------------------
@app.get("/")
def root():
    return jsonify({"service": SERVICE_NAME, "status": "ok"})


@app.get("/health")
def health():
    return jsonify({"service": SERVICE_NAME, "status": "ok"})


# ------------------------------------------------------------
# WEBHOOK VERIFY (Meta)
# ------------------------------------------------------------
@app.get("/webhook")
def webhook_verify():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == WHATSAPP_VERIFY_TOKEN:
        return challenge, 200
    return "Forbidden", 403


# ------------------------------------------------------------
# WEBHOOK RECEIVE (Meta)
# ------------------------------------------------------------
@app.post("/webhook")
def webhook_receive():
    payload = request.get_json(silent=True) or {}

    try:
        entries = payload.get("entry", [])
        for entry in entries:
            for change in entry.get("changes", []):
                value = change.get("value", {})
                for msg in (value.get("messages") or []):
                    wa_phone = msg.get("from")
                    if not wa_phone:
                        continue

                    upsert_user_profile(wa_phone)

                    if msg.get("type") != "text":
                        send_reply(wa_phone, "Please send a text message. Type *menu* to begin.")
                        continue

                    text = (msg.get("text") or {}).get("body", "")
                    handle_inbound(wa_phone, text, msg)

        return jsonify({"status": "ok"}), 200

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


def handle_inbound(wa_phone: str, message_text: str, raw_msg: Dict[str, Any]) -> None:
    text = safe_text(message_text)
    log_event(wa_phone, "INBOUND", {"text": text[:200]})

    # Commands
    cmd = handle_command(text)
    if cmd:
        if cmd.get("action") == "cancel":
            close_active_session(wa_phone, reason="cancelled")
            send_reply(wa_phone, "❌ Session cancelled. Type *menu* to start again.")
            return

        if cmd.get("action") == "restart":
            close_active_session(wa_phone, reason="restarted")
            send_reply(wa_phone, "🔄 Restarted. Type *menu* to continue.")
            return

        if cmd.get("action") == "upgrade":
            send_reply(wa_phone, upgrade_message())
            return

        send_reply(wa_phone, cmd["reply"])
        return

    # Upgrade keyword variants
    lower = text.lower()
    if lower == "upgrade":
        send_reply(wa_phone, upgrade_message())
        return

    if lower.startswith("upgrade "):
        plan = lower.replace("upgrade", "").strip()
        if plan not in PLAN_PRICES:
            send_reply(wa_phone, "❌ Invalid plan. Reply: UPGRADE BASIC or UPGRADE PRO")
            return

        try:
            p = create_payment_record(wa_phone, plan)
            send_reply(
                wa_phone,
                "✅ Upgrade initialized.\n\n"
                f"Plan: {plan.upper()}\n"
                f"Reference: {p['reference']}\n\n"
                "Next: we will connect Paystack to generate a payment link.\n"
                "Type *menu* to continue using the bot."
            )
            log_event(wa_phone, "UPGRADE_INIT", {"plan": plan, "reference": p["reference"]})
        except Exception:
            send_reply(wa_phone, "❌ Could not initialize upgrade. Try again later.")
        return

    # Active session
    active = get_active_session(wa_phone)
    if active and session_expired(active):
        close_active_session(wa_phone, reason="expired")
        active = None

    # New flow start
    flow_key = detect_flow_start(text)
    if flow_key:
        user_plan = get_user_plan(wa_phone)

        # Enforcement (before starting a flow)
        if not can_use_flow(user_plan, flow_key):
            send_reply(
                wa_phone,
                "🔒 This feature requires a paid plan.\nReply *UPGRADE* to continue."
            )
            log_event(wa_phone, "GATED_FLOW", {"flow": flow_key, "plan": user_plan})
            return

        close_active_session(wa_phone, reason="switched_flow")
        session = create_session(wa_phone, flow_key)
        log_event(wa_phone, "FLOW_STARTED", {"flow": flow_key})

        reply, patch = route_flow(session, "")
        if patch and session.get("id"):
            update_session(session["id"], patch)
        send_reply(wa_phone, reply)
        return

    # No flow + no session
    if not active:
        send_reply(
            wa_phone,
            "Type *menu* to begin.\n\nQuick start:\n• VAT\n• PAYE\n• BUSINESS\n• GUIDE"
        )
        return

    # Continue flow
    try:
        update_session(active["id"], {"last_inbound_at": iso(now_utc())})
    except Exception:
        pass

    reply, patch = route_flow(active, text)
    if patch:
        try:
            update_session(active["id"], patch)
        except Exception:
            pass

    send_reply(wa_phone, reply)
    log_event(wa_phone, "OUTBOUND", {"flow": active.get("flow_key")})


# Local run (optional)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
