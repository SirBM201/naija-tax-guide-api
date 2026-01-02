import os
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import requests
from flask import Flask, request, jsonify

# Supabase python client
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

SERVICE_NAME = os.getenv("SERVICE_NAME", "naija-tax-guide-api")

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY")
if not WHATSAPP_TOKEN or not WHATSAPP_PHONE_NUMBER_ID or not WHATSAPP_VERIFY_TOKEN:
    raise RuntimeError("Missing WHATSAPP_TOKEN or WHATSAPP_PHONE_NUMBER_ID or WHATSAPP_VERIFY_TOKEN")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

WA_MESSAGES_URL = f"https://graph.facebook.com/v21.0/{WHATSAPP_PHONE_NUMBER_ID}/messages"
DEFAULT_SESSION_TTL_HOURS = int(os.getenv("SESSION_TTL_HOURS", "24"))


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def safe_text(s: Any) -> str:
    return (s or "").strip()


def send_reply(wa_phone: str, text: str) -> None:
    """Send a WhatsApp text message via Cloud API."""
    payload = {
        "messaging_product": "whatsapp",
        "to": wa_phone,
        "type": "text",
        "text": {"body": text},
    }
    headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}", "Content-Type": "application/json"}
    r = requests.post(WA_MESSAGES_URL, headers=headers, json=payload, timeout=30)
    # If you want, you can log r.status_code / r.text to Supabase events.
    return


def log_event(wa_phone: str, event: str, meta: Optional[Dict[str, Any]] = None) -> None:
    """Lightweight analytics. Safe to fail silently."""
    try:
        supabase.table("events").insert({
            "wa_phone": wa_phone,
            "event": event,
            "meta": meta or {}
        }).execute()
    except Exception:
        pass


# ------------------------------------------------------------
# 1) User Profile (one row per phone)
# ------------------------------------------------------------
def upsert_user_profile(wa_phone: str) -> None:
    """Ensure one user row exists for each phone. Minimal fields for now."""
    try:
        supabase.table("users").upsert({
            "wa_phone": wa_phone,
            "last_seen_at": now_utc().isoformat(),
        }, on_conflict="wa_phone").execute()
    except Exception:
        # Don't block the bot if profile fails
        pass


def get_user_plan(wa_phone: str) -> str:
    """
    Subscription plan lookup.
    Table: user_subscriptions (wa_phone PK, plan text, expires_at timestamptz)
    If missing or expired -> free
    """
    try:
        res = supabase.table("user_subscriptions") \
            .select("plan, expires_at") \
            .eq("wa_phone", wa_phone) \
            .limit(1) \
            .execute()

        if not res.data:
            return "free"

        row = res.data[0]
        plan = row.get("plan") or "free"
        expires_at = row.get("expires_at")

        if expires_at:
            # if expires_at is passed, downgrade
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
# 2) Guard / Monetization Gate (foundation)
# ------------------------------------------------------------
def can_use_flow(user_plan: str, flow_key: str) -> bool:
    """
    Start permissive. Tighten later by editing FREE_LIMITED.
    Example:
      FREE_LIMITED = ["hustler_onboarding"]
      if user_plan == "free" and flow_key not in FREE_LIMITED: return False
    """
    FREE_LIMITED = ["hustler_onboarding", "vat", "menu"]  # keep MVP usable
    if user_plan == "free":
        return flow_key in FREE_LIMITED
    return True


# ------------------------------------------------------------
# 3) Sessions (Supabase flow_sessions)
# Your actual columns (based on your screenshot):
# id, wa_phone, user_id, flow_key, status, current_step, step_index,
# context, meta, locked_by, locked_at, last_inbound_at, last_outbound_at,
# expires_at, created_at, updated_at
# ------------------------------------------------------------
def get_active_session(wa_phone: str) -> Optional[Dict[str, Any]]:
    try:
        res = supabase.table("flow_sessions") \
            .select("*") \
            .eq("wa_phone", wa_phone) \
            .eq("status", "active") \
            .order("updated_at", desc=True) \
            .limit(1) \
            .execute()
        if not res.data:
            return None
        return res.data[0]
    except Exception:
        return None


def close_active_session(wa_phone: str, reason: str = "closed") -> None:
    try:
        # close ALL active sessions for this phone (simple + safe)
        supabase.table("flow_sessions") \
            .update({"status": reason, "updated_at": now_utc().isoformat()}) \
            .eq("wa_phone", wa_phone) \
            .eq("status", "active") \
            .execute()
    except Exception:
        pass


def create_session(wa_phone: str, flow_key: str) -> Dict[str, Any]:
    expires_at = (now_utc() + timedelta(hours=DEFAULT_SESSION_TTL_HOURS)).isoformat()
    row = {
        "wa_phone": wa_phone,
        "flow_key": flow_key,
        "status": "active",
        "current_step": "START",
        "step_index": 1,
        "context": {},
        "meta": {},
        "last_inbound_at": now_utc().isoformat(),
        "expires_at": expires_at,
        "updated_at": now_utc().isoformat(),
    }
    res = supabase.table("flow_sessions").insert(row).execute()
    return res.data[0] if res.data else row


def update_session(session_id: Any, patch: Dict[str, Any]) -> None:
    patch["updated_at"] = now_utc().isoformat()
    supabase.table("flow_sessions").update(patch).eq("id", session_id).execute()


# ------------------------------------------------------------
# 4) Commands / Menu
# ------------------------------------------------------------
def handle_command(message_text: str) -> Optional[Dict[str, Any]]:
    cmd = safe_text(message_text).lower()

    if cmd in ["menu", "help", "start"]:
        return {
            "reply": (
                "📌 *Naija Hustle Tax Guide*\n\n"
                "Reply with any option:\n"
                "• VAT – VAT calculator\n"
                "• BUSINESS – Hustler onboarding\n"
                "• PAYE – Salary tax (coming next)\n\n"
                "Commands:\n"
                "• restart – start over\n"
                "• cancel – end session"
            )
        }

    if cmd == "restart":
        return {"action": "restart"}

    if cmd == "cancel":
        return {"action": "cancel"}

    return None


def detect_flow_start(message_text: str) -> Optional[str]:
    t = safe_text(message_text).lower()
    if t in ["vat", "vat calculator"]:
        return "vat"
    if t in ["business", "hustle", "hustler", "hustler onboarding"]:
        return "hustler_onboarding"
    if t in ["paye", "salary", "salary tax"]:
        return "paye"
    return None


# ------------------------------------------------------------
# VAT Flow
# Steps:
#   VAT_ASK_SALES -> VAT_ASK_INPUT -> VAT_SHOW
# ------------------------------------------------------------
def vat_flow_reply(session: Dict[str, Any], message_text: str) -> Tuple[str, Dict[str, Any]]:
    context = session.get("context") or {}
    step = session.get("current_step") or "START"

    t = safe_text(message_text)

    if step in ["START", "VAT_ASK_SALES"]:
        patch = {"current_step": "VAT_ASK_SALES", "step_index": 1}
        reply = (
            "✅ *VAT Calculator (Nigeria)*\n\n"
            "Enter your *total sales/turnover amount* (₦).\n"
            "Example: 1500000"
        )
        return reply, patch

    if step == "VAT_ASK_SALES":
        try:
            sales = float(t.replace(",", ""))
            if sales < 0:
                raise ValueError("neg")
            context["sales"] = sales
            patch = {"current_step": "VAT_ASK_INPUT", "step_index": 2, "context": context}
            reply = (
                f"Sales recorded: ₦{sales:,.2f}\n\n"
                "Now enter your *VAT paid on purchases (input VAT)* (₦).\n"
                "If none, reply 0."
            )
            return reply, patch
        except Exception:
            return "❌ Please enter a valid number for sales (example: 1500000).", {}

    if step == "VAT_ASK_INPUT":
        try:
            input_vat = float(t.replace(",", ""))
            if input_vat < 0:
                raise ValueError("neg")
            sales = float(context.get("sales", 0))
            vat_rate = 0.075  # 7.5%
            output_vat = sales * vat_rate
            net = output_vat - input_vat

            context.update({
                "input_vat": input_vat,
                "output_vat": output_vat,
                "net_vat": net
            })

            patch = {"current_step": "VAT_SHOW", "step_index": 3, "context": context}

            if net >= 0:
                verdict = f"✅ *Estimated VAT payable:* ₦{net:,.2f}"
            else:
                verdict = f"✅ *Estimated VAT credit/refund:* ₦{abs(net):,.2f}"

            reply = (
                "📊 *VAT Summary*\n\n"
                f"• Sales: ₦{sales:,.2f}\n"
                f"• Output VAT (7.5%): ₦{output_vat:,.2f}\n"
                f"• Input VAT: ₦{input_vat:,.2f}\n\n"
                f"{verdict}\n\n"
                "Type *menu* for more options or *restart* to run again."
            )
            return reply, patch
        except Exception:
            return "❌ Please enter a valid number for input VAT (example: 25000).", {}

    # fallback
    return "Type *menu* to start.", {"current_step": "START", "step_index": 1}


def hustle_onboarding_reply(session: Dict[str, Any], message_text: str) -> Tuple[str, Dict[str, Any]]:
    """
    Simple placeholder onboarding flow.
    We'll expand this next (business type, state, registration, turnover, etc.)
    """
    context = session.get("context") or {}
    step = session.get("current_step") or "START"
    t = safe_text(message_text)

    if step in ["START", "HB_ASK_TYPE"]:
        patch = {"current_step": "HB_ASK_TYPE", "step_index": 1}
        reply = (
            "✅ *Hustler Onboarding*\n\n"
            "What do you do?\n"
            "Reply with a short description.\n"
            "Example: POS agent / Fashion / Food / Freelancer"
        )
        return reply, patch

    if step == "HB_ASK_TYPE":
        context["business_type"] = t
        patch = {"current_step": "HB_ASK_STATE", "step_index": 2, "context": context}
        reply = "Which state are you operating from in Nigeria? (e.g., Lagos, Kano, Rivers)"
        return reply, patch

    if step == "HB_ASK_STATE":
        context["state"] = t
        patch = {"current_step": "HB_DONE", "step_index": 3, "context": context}
        reply = (
            "✅ Onboarding saved.\n\n"
            f"• Business: {context.get('business_type')}\n"
            f"• State: {context.get('state')}\n\n"
            "Next: we will suggest the most relevant taxes + record-keeping tips.\n"
            "Type *menu* to continue."
        )
        return reply, patch

    return "Type *menu* to start.", {"current_step": "START", "step_index": 1}


def paye_reply(session: Dict[str, Any], message_text: str) -> Tuple[str, Dict[str, Any]]:
    # Placeholder: we implement PAYE properly in the next block.
    return (
        "PAYE is next. For now, use:\n"
        "• VAT (calculator)\n"
        "• BUSINESS (onboarding)\n\n"
        "Type *menu* to continue.",
        {}
    )


def route_flow(session: Dict[str, Any], message_text: str) -> Tuple[str, Dict[str, Any]]:
    flow_key = session.get("flow_key")
    if flow_key == "vat":
        return vat_flow_reply(session, message_text)
    if flow_key == "hustler_onboarding":
        return hustle_onboarding_reply(session, message_text)
    if flow_key == "paye":
        return paye_reply(session, message_text)
    return ("Type *menu* to start.", {})


# ------------------------------------------------------------
# 5) Expiry cleanup endpoint (manual/cron)
# ------------------------------------------------------------
@app.get("/tasks/expire_sessions")
def expire_sessions():
    """
    Optional endpoint you can call manually or from a cron
    to mark old sessions as expired.
    """
    try:
        cutoff = (now_utc() - timedelta(hours=DEFAULT_SESSION_TTL_HOURS)).isoformat()

        # expire active sessions past expires_at OR inactive beyond cutoff
        supabase.table("flow_sessions") \
            .update({"status": "expired", "updated_at": now_utc().isoformat()}) \
            .eq("status", "active") \
            .lt("expires_at", now_utc().isoformat()) \
            .execute()

        supabase.table("flow_sessions") \
            .update({"status": "expired", "updated_at": now_utc().isoformat()}) \
            .eq("status", "active") \
            .lt("last_inbound_at", cutoff) \
            .execute()

        return jsonify({"status": "ok", "task": "expire_sessions"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


# ------------------------------------------------------------
# Health / Root
# ------------------------------------------------------------
@app.get("/")
def root():
    return jsonify({"service": SERVICE_NAME, "status": "ok"})


@app.get("/health")
def health():
    return jsonify({"service": SERVICE_NAME, "status": "ok"})


# ------------------------------------------------------------
# Webhook Verification (Meta)
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
# Webhook Receive (Meta)
# ------------------------------------------------------------
@app.post("/webhook")
def webhook_receive():
    payload = request.get_json(silent=True) or {}
    # You can log payload for debugging if needed:
    # print(json.dumps(payload))

    try:
        entries = payload.get("entry", [])
        for entry in entries:
            changes = entry.get("changes", [])
            for change in changes:
                value = change.get("value", {})
                messages = value.get("messages", [])
                for msg in messages:
                    wa_phone = msg.get("from")
                    if not wa_phone:
                        continue

                    # Track profile
                    upsert_user_profile(wa_phone)

                    # Extract message text
                    message_text = ""
                    if msg.get("type") == "text":
                        message_text = msg.get("text", {}).get("body", "")
                    else:
                        # Ignore non-text for now
                        send_reply(wa_phone, "Please send a text message. Type *menu* to begin.")
                        continue

                    handle_inbound(wa_phone, message_text, msg)

        return jsonify({"status": "ok"}), 200

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


def handle_inbound(wa_phone: str, message_text: str, raw_msg: Dict[str, Any]) -> None:
    text = safe_text(message_text)
    log_event(wa_phone, "INBOUND", {"text": text[:200]})

    # 1) Global command handling
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

        send_reply(wa_phone, cmd["reply"])
        return

    # 2) Upgrade keyword (foundation)
    if text.lower() == "upgrade":
        send_reply(
            wa_phone,
            "💳 Upgrade is coming next.\n\n"
            "For now, you can use:\n"
            "• VAT\n"
            "• BUSINESS\n\n"
            "Type *menu* to continue."
        )
        log_event(wa_phone, "UPGRADE_INTENT")
        return

    # 3) Expire old sessions (soft)
    # If you want to be strict, rely on expires_at checks inside DB cleanup.
    # Here we just close if expires_at passed (best effort).
    active = get_active_session(wa_phone)
    if active and active.get("expires_at"):
        try:
            exp = datetime.fromisoformat(active["expires_at"].replace("Z", "+00:00"))
            if exp < now_utc():
                close_active_session(wa_phone, reason="expired")
                active = None
        except Exception:
            pass

    # 4) Detect new flow start
    flow_key = detect_flow_start(text)

    # If user typed VAT/BUSINESS/PAYE, start that flow (close old session first)
    if flow_key:
        user_plan = get_user_plan(wa_phone)

        # Gate check (before starting a flow)
        if not can_use_flow(user_plan, flow_key):
            send_reply(
                wa_phone,
                "🔒 This feature requires a paid plan.\n"
                "Reply *UPGRADE* to continue."
            )
            log_event(wa_phone, "GATED_FLOW", {"flow": flow_key, "plan": user_plan})
            return

        close_active_session(wa_phone, reason="switched_flow")
        session = create_session(wa_phone, flow_key)
        log_event(wa_phone, "FLOW_STARTED", {"flow": flow_key})

        reply, patch = route_flow(session, "")  # empty to trigger START prompt
        if patch:
            update_session(session["id"], patch)

        send_reply(wa_phone, reply)
        return

    # 5) Continue existing session, else show menu
    if not active:
        send_reply(
            wa_phone,
            "Type *menu* to begin.\n\n"
            "Quick start:\n"
            "• VAT\n"
            "• BUSINESS"
        )
        return

    # Update inbound timestamp
    try:
        update_session(active["id"], {"last_inbound_at": now_utc().isoformat()})
    except Exception:
        pass

    reply, patch = route_flow(active, text)
    if patch:
        update_session(active["id"], patch)

    send_reply(wa_phone, reply)
    log_event(wa_phone, "OUTBOUND", {"flow": active.get("flow_key")})


# For local dev only:
# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
