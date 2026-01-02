import os
from datetime import datetime, timedelta, timezone

from flask import Flask, request, jsonify, make_response

from supabase import create_client, Client

app = Flask(__name__)

# ---------------------------
# ENV
# ---------------------------
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "naija-tax-guide-verify")

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in environment variables")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# Session expiry window for MVP
SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "30"))


# ---------------------------
# HEALTH
# ---------------------------
@app.get("/")
def root():
    return jsonify({"service": "naija-tax-guide-api", "status": "ok"})


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


# ---------------------------
# META WEBHOOK VERIFY (GET)
# ---------------------------
@app.get("/webhook")
def webhook_verify():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == VERIFY_TOKEN and challenge:
        return make_response(challenge, 200)

    return make_response("Forbidden", 403)


# ---------------------------
# HELPERS: FLOW SESSIONS
# ---------------------------
def utcnow():
    return datetime.now(timezone.utc)


def ensure_single_active_session(wa_phone: str, flow_key: str = "menu"):
    """
    One ACTIVE session per phone (global).
    If exists => return it.
    If not => create it.
    """
    # Get active
    res = (
        supabase.table("flow_sessions")
        .select("*")
        .eq("wa_phone", wa_phone)
        .eq("status", "active")
        .limit(1)
        .execute()
    )

    if res.data and len(res.data) > 0:
        return res.data[0]

    # Create new
    now = utcnow()
    expires_at = now + timedelta(minutes=SESSION_TTL_MINUTES)

    payload = {
        "wa_phone": wa_phone,
        "flow_key": flow_key,
        "status": "active",
        "current_step": "START",
        "step_index": 1,
        "context": {},
        "meta": {},
        "last_inbound_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
    }

    ins = supabase.table("flow_sessions").insert(payload).execute()
    return ins.data[0]


def update_session(session_id: str, **fields):
    fields["updated_at"] = utcnow().isoformat()
    upd = supabase.table("flow_sessions").update(fields).eq("id", session_id).execute()
    return upd.data[0] if upd.data else None


def expire_session(session_id: str):
    return update_session(session_id, status="expired")


# ---------------------------
# SIMPLE MVP FLOW LOGIC
# ---------------------------
def handle_flow(session: dict, user_text: str) -> str:
    """
    Replace this with your full Guide + Calculators flows.
    """
    step = session.get("current_step", "START")
    text = (user_text or "").strip().lower()

    # START → show menu
    if step == "START":
        update_session(
            session["id"],
            current_step="MENU",
            step_index=1,
        )
        return (
            "Welcome to Naija Hustle Tax Guide.\n"
            "Reply with:\n"
            "1) PAYE Calculator\n"
            "2) VAT Guide\n"
            "3) Business Tax Basics\n"
            "0) Restart"
        )

    if text == "0":
        expire_session(session["id"])
        new_sess = ensure_single_active_session(session["wa_phone"], flow_key="menu")
        return handle_flow(new_sess, "")  # triggers menu

    if step == "MENU":
        if text == "1":
            update_session(session["id"], flow_key="paye", current_step="PAYE_ASK_MONTHLY", step_index=1)
            return "PAYE Calculator:\nHow much is your monthly salary (₦)? (numbers only)"
        if text == "2":
            update_session(session["id"], flow_key="vat", current_step="VAT_INFO", step_index=1)
            return "VAT Guide:\nVAT in Nigeria is charged on eligible goods/services. Reply 'menu' to go back."
        if text == "3":
            update_session(session["id"], flow_key="biz_tax", current_step="BIZ_TAX_INFO", step_index=1)
            return "Business Tax Basics:\nReply 'menu' to go back."
        return "Invalid option. Reply 1, 2, 3 or 0."

    if text == "menu":
        update_session(session["id"], flow_key="menu", current_step="MENU", step_index=1)
        return (
            "Main Menu:\n"
            "1) PAYE Calculator\n"
            "2) VAT Guide\n"
            "3) Business Tax Basics\n"
            "0) Restart"
        )

    # PAYE example (placeholder)
    if session.get("flow_key") == "paye" and step == "PAYE_ASK_MONTHLY":
        # For now just store input; calculator comes next step
        try:
            salary = float(text.replace(",", ""))
        except Exception:
            return "Please enter a valid number for monthly salary (e.g., 250000)."

        ctx = session.get("context") or {}
        ctx["monthly_salary"] = salary

        update_session(session["id"], context=ctx, current_step="PAYE_DONE", step_index=2)
        return (
            f"Saved monthly salary: ₦{salary:,.0f}\n"
            "Next: we will calculate PAYE using Nigerian tax bands.\n"
            "Reply 'menu' to go back."
        )

    return "Reply 'menu' to see options or '0' to restart."


# ---------------------------
# INBOUND WEBHOOK (POST)
# ---------------------------
@app.post("/webhook")
def webhook_inbound():
    """
    Meta will POST messages here.
    For MVP, we’ll parse minimal fields.
    """
    payload = request.get_json(silent=True) or {}

    # Very defensive parsing (Meta payload structure varies by product/version)
    try:
        entry = (payload.get("entry") or [])[0]
        changes = (entry.get("changes") or [])[0]
        value = changes.get("value") or {}

        messages = value.get("messages") or []
        if not messages:
            # Delivery receipts, statuses etc.
            return jsonify({"ok": True})

        msg = messages[0]
        wa_phone = msg.get("from")  # WhatsApp user phone
        text_body = (msg.get("text") or {}).get("body", "")

        if not wa_phone:
            return jsonify({"ok": True})

        session = ensure_single_active_session(wa_phone, flow_key="menu")

        # Update last inbound + refresh expiry
        now = utcnow()
        expires_at = now + timedelta(minutes=SESSION_TTL_MINUTES)
        update_session(session["id"], last_inbound_at=now.isoformat(), expires_at=expires_at.isoformat())

        reply_text = handle_flow(session, text_body)

        # NOTE:
        # Actual sending back to WhatsApp requires calling Meta /messages API.
        # For now we return the reply so you can test logic quickly.
        return jsonify({"ok": True, "to": wa_phone, "reply": reply_text})

    except Exception as e:
        # Do not crash webhook
        return jsonify({"ok": False, "error": str(e)}), 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
