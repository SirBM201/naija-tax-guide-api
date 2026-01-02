import os
import hmac
import hashlib
from datetime import datetime, timedelta, timezone

from flask import Flask, request, abort, jsonify
from supabase import create_client, Client

# ------------------------------------------------------------
# App
# ------------------------------------------------------------
app = Flask(__name__)

# ------------------------------------------------------------
# ENV VARS (Koyeb)
# ------------------------------------------------------------
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "naija-tax-guide-verify")
APP_SECRET = os.getenv("META_APP_SECRET", "")  # Meta App Secret (optional but recommended)

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    # Fail fast: backend cannot work without DB
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY env vars.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# Session defaults
SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "120"))

# ------------------------------------------------------------
# Health checks
# ------------------------------------------------------------
@app.get("/")
def root():
    return jsonify({"service": "naija-tax-guide-api", "status": "ok"}), 200

@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200

# ------------------------------------------------------------
# Security: verify Meta signature (X-Hub-Signature-256)
# ------------------------------------------------------------
def verify_signature(req) -> bool:
    """
    Verifies Meta webhook signature (X-Hub-Signature-256).
    If META_APP_SECRET is not set, verification is skipped (OK for dev; not ideal for prod).
    """
    if not APP_SECRET:
        return True

    signature = req.headers.get("X-Hub-Signature-256", "")
    if not signature.startswith("sha256="):
        return False

    provided_hash = signature.split("=", 1)[1]
    payload = req.get_data()  # raw bytes

    expected_hash = hmac.new(
        APP_SECRET.encode("utf-8"),
        msg=payload,
        digestmod=hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(provided_hash, expected_hash)

# ------------------------------------------------------------
# Helpers: WhatsApp payload parsing (Meta Cloud API)
# ------------------------------------------------------------
def extract_inbound_text(meta_payload: dict) -> dict:
    """
    Extracts a single inbound message:
    returns { "wa_phone": "...", "text": "...", "message_id": "...", "raw": {...} }
    If no inbound user message exists, returns {}.
    """
    try:
        entry = (meta_payload.get("entry") or [])[0]
        change = (entry.get("changes") or [])[0]
        value = change.get("value") or {}

        messages = value.get("messages") or []
        if not messages:
            return {}

        msg = messages[0]
        wa_phone = msg.get("from")  # sender wa id (phone)
        msg_id = msg.get("id")

        mtype = msg.get("type")
        text = ""

        if mtype == "text":
            text = ((msg.get("text") or {}).get("body") or "").strip()
        elif mtype == "button":
            text = ((msg.get("button") or {}).get("text") or "").strip()
        elif mtype == "interactive":
            # list replies / button replies
            inter = msg.get("interactive") or {}
            i_type = inter.get("type")
            if i_type == "list_reply":
                text = (((inter.get("list_reply") or {}).get("title")) or "").strip()
            elif i_type == "button_reply":
                text = (((inter.get("button_reply") or {}).get("title")) or "").strip()
        else:
            # unsupported types: image/audio/location/etc.
            text = ""

        return {
            "wa_phone": wa_phone,
            "text": text,
            "message_id": msg_id,
            "raw": msg,
            "value": value,
        }
    except Exception:
        return {}

def now_utc():
    return datetime.now(timezone.utc)

def expires_at_utc(minutes: int):
    return now_utc() + timedelta(minutes=minutes)

# ------------------------------------------------------------
# DB: Users
# ------------------------------------------------------------
def get_or_create_user(wa_phone: str) -> dict:
    res = supabase.table("wa_users").select("*").eq("wa_phone", wa_phone).limit(1).execute()
    if res.data:
        return res.data[0]

    created = supabase.table("wa_users").insert({
        "wa_phone": wa_phone,
        "created_at": now_utc().isoformat(),
        "updated_at": now_utc().isoformat(),
    }).execute()
    return created.data[0]

# ------------------------------------------------------------
# DB: Sessions (ONE active per phone - global)
# ------------------------------------------------------------
def get_active_session(wa_phone: str) -> dict | None:
    res = (
        supabase.table("flow_sessions")
        .select("*")
        .eq("wa_phone", wa_phone)
        .eq("status", "active")
        .order("updated_at", desc=True)
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None

def create_session(wa_phone: str, user_id: int, flow_key: str = "menu") -> dict:
    payload = {
        "wa_phone": wa_phone,
        "user_id": user_id,
        "flow_key": flow_key,
        "status": "active",
        "current_step": "start",
        "step_index": 0,
        "context": {},
        "meta": {},
        "last_inbound_at": now_utc().isoformat(),
        "expires_at": expires_at_utc(SESSION_TTL_MINUTES).isoformat(),
        "created_at": now_utc().isoformat(),
        "updated_at": now_utc().isoformat(),
    }
    res = supabase.table("flow_sessions").insert(payload).execute()
    return res.data[0]

def update_session(session_id: str, patch: dict) -> dict:
    patch = dict(patch)
    patch["updated_at"] = now_utc().isoformat()
    res = supabase.table("flow_sessions").update(patch).eq("id", session_id).execute()
    return res.data[0]

def end_session(session_id: str, status: str = "completed") -> None:
    supabase.table("flow_sessions").update({
        "status": status,
        "updated_at": now_utc().isoformat(),
        "expires_at": now_utc().isoformat()
    }).eq("id", session_id).execute()

# ------------------------------------------------------------
# DB: Message log
# ------------------------------------------------------------
def log_message(wa_phone: str, direction: str, text: str, payload: dict, session_id: str | None, message_id: str | None):
    supabase.table("flow_messages").insert({
        "wa_phone": wa_phone,
        "direction": direction,
        "text": text,
        "payload": payload or {},
        "session_id": session_id,
        "message_id": message_id,
        "created_at": now_utc().isoformat(),
    }).execute()

# ------------------------------------------------------------
# Flow Engine: MENU + PAYE Calculator (starter)
# ------------------------------------------------------------
def normalize(s: str) -> str:
    return (s or "").strip().lower()

def parse_money(text: str) -> float | None:
    """
    Accepts inputs like:
    500000
    500,000
    500000.50
    """
    t = (text or "").strip().replace(",", "")
    try:
        val = float(t)
        if val < 0:
            return None
        return val
    except Exception:
        return None

def compute_paye_placeholder(gross: float, pension: float = 0.0, nhf: float = 0.0) -> dict:
    """
    Placeholder calculation. We will replace with the real PAYE logic next.
    For now, returns the captured inputs and a simple taxable estimate.
    """
    taxable = max(gross - pension - nhf, 0.0)
    return {
        "gross": gross,
        "pension": pension,
        "nhf": nhf,
        "taxable_estimate": taxable
    }

def handle_flow(session: dict, inbound_text: str) -> tuple[str, dict]:
    """
    Returns (reply_text, session_patch)
    session_patch will be merged into DB update.
    """
    flow_key = session.get("flow_key", "menu")
    step = session.get("current_step", "start")
    ctx = session.get("context") or {}

    t = normalize(inbound_text)

    # Global commands
    if t in {"menu", "start", "home"}:
        return (
            "Naija Hustle Tax Guide\n"
            "Reply with a number:\n"
            "1) Calculators\n"
            "2) Guides\n"
            "3) Help\n\n"
            "Type MENU anytime to return here.",
            {
                "flow_key": "menu",
                "current_step": "main_menu",
                "step_index": 0,
                "context": {},
                "expires_at": expires_at_utc(SESSION_TTL_MINUTES).isoformat(),
            }
        )

    if t in {"cancel", "stop"}:
        return (
            "Session cancelled. Type MENU to start again.",
            {
                "status": "cancelled",
                "expires_at": now_utc().isoformat(),
            }
        )

    # -------------------------
    # MENU flow
    # -------------------------
    if flow_key == "menu":
        if step in {"start", "main_menu"}:
            if t in {"1", "calculators", "calc"}:
                return (
                    "Calculators\n"
                    "Reply with a number:\n"
                    "1) PAYE (Salary Tax)\n"
                    "2) VAT\n"
                    "3) Withholding Tax (WHT)\n\n"
                    "Type MENU to go back.",
                    {
                        "current_step": "calc_menu",
                        "step_index": 1,
                        "expires_at": expires_at_utc(SESSION_TTL_MINUTES).isoformat(),
                    }
                )
            if t in {"2", "guides", "guide"}:
                return (
                    "Guides\n"
                    "Reply with a number:\n"
                    "1) PAYE Guide\n"
                    "2) VAT Guide\n"
                    "3) Filing & Compliance\n\n"
                    "Type MENU to go back.",
                    {
                        "current_step": "guides_menu",
                        "step_index": 1,
                        "expires_at": expires_at_utc(SESSION_TTL_MINUTES).isoformat(),
                    }
                )
            if t in {"3", "help"}:
                return (
                    "Help\n"
                    "- Type MENU anytime to return home\n"
                    "- Type CANCEL to stop a session\n"
                    "- Use numbers to select options\n\n"
                    "Reply MENU to continue.",
                    {
                        "current_step": "help",
                        "step_index": 1,
                        "expires_at": expires_at_utc(SESSION_TTL_MINUTES).isoformat(),
                    }
                )

            return ("Please reply with 1, 2, or 3. Type MENU to restart.", {})

        if step == "calc_menu":
            if t in {"1", "paye"}:
                return (
                    "PAYE Calculator\n"
                    "Enter your monthly GROSS salary (e.g., 500000):",
                    {
                        "flow_key": "paye_calc",
                        "current_step": "ask_gross",
                        "step_index": 0,
                        "context": {},
                        "expires_at": expires_at_utc(SESSION_TTL_MINUTES).isoformat(),
                    }
                )
            if t in {"2", "vat"}:
                return ("VAT calculator is next. Type MENU for now.", {})
            if t in {"3", "wht"}:
                return ("WHT calculator is next. Type MENU for now.", {})

            return ("Please reply with 1, 2, or 3. Type MENU to go back.", {})

        if step == "guides_menu":
            # We’ll implement guides as content retrieval next
            return ("Guides will be added next. Type MENU to go back.", {})

        return ("Type MENU to begin.", {})

    # -------------------------
    # PAYE calculator flow (multi-step)
    # -------------------------
    if flow_key == "paye_calc":
        if step == "ask_gross":
            gross = parse_money(inbound_text)
            if gross is None or gross <= 0:
                return ("Please enter a valid gross amount (example: 500000).", {})
            ctx["gross"] = gross
            return (
                "Enter your monthly PENSION amount (enter 0 if none):",
                {
                    "current_step": "ask_pension",
                    "step_index": 1,
                    "context": ctx,
                    "expires_at": expires_at_utc(SESSION_TTL_MINUTES).isoformat(),
                }
            )

        if step == "ask_pension":
            pension = parse_money(inbound_text)
            if pension is None or pension < 0:
                return ("Please enter a valid pension amount (example: 20000) or 0.", {})
            ctx["pension"] = pension
            return (
                "Enter your monthly NHF amount (enter 0 if none):",
                {
                    "current_step": "ask_nhf",
                    "step_index": 2,
                    "context": ctx,
                    "expires_at": expires_at_utc(SESSION_TTL_MINUTES).isoformat(),
                }
            )

        if step == "ask_nhf":
            nhf = parse_money(inbound_text)
            if nhf is None or nhf < 0:
                return ("Please enter a valid NHF amount or 0.", {})
            ctx["nhf"] = nhf

            result = compute_paye_placeholder(
                gross=float(ctx.get("gross", 0)),
                pension=float(ctx.get("pension", 0)),
                nhf=float(ctx.get("nhf", 0)),
            )

            # We end this calculator session after result for cleanliness
            reply = (
                "PAYE Calculator (Draft Result)\n"
                f"- Gross: {result['gross']:,}\n"
                f"- Pension: {result['pension']:,}\n"
                f"- NHF: {result['nhf']:,}\n"
                f"- Taxable Estimate: {result['taxable_estimate']:,}\n\n"
                "Next: I will plug in the correct PAYE bands + CRA rules.\n"
                "Type MENU to do another calculation."
            )
            return (
                reply,
                {
                    "current_step": "done",
                    "status": "completed",
                    "context": ctx,
                    "expires_at": now_utc().isoformat(),
                }
            )

        return ("Type MENU to start over.", {})

    # Fallback
    return ("Type MENU to begin.", {})

# ------------------------------------------------------------
# Webhook
# ------------------------------------------------------------
@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    # ---- Webhook verification (Meta) ----
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")

        if mode == "subscribe" and token == VERIFY_TOKEN:
            return (challenge or ""), 200
        return abort(403)

    # ---- Incoming events ----
    if request.method == "POST":
        if not verify_signature(request):
            return abort(403)

        payload = request.get_json(silent=True) or {}

        inbound = extract_inbound_text(payload)
        if not inbound:
            # This can happen for status updates (delivered/read) etc.
            return "EVENT_RECEIVED", 200

        wa_phone = inbound["wa_phone"]
        text = inbound["text"]
        meta_msg_id = inbound["message_id"]

        # log inbound
        log_message(
            wa_phone=wa_phone,
            direction="inbound",
            text=text,
            payload=inbound.get("raw") or {},
            session_id=None,
            message_id=meta_msg_id
        )

        # ensure user
        user = get_or_create_user(wa_phone)
        session = get_active_session(wa_phone)

        # if none, create session and show menu immediately
        if not session:
            session = create_session(wa_phone=wa_phone, user_id=user["id"], flow_key="menu")

        # handle flow
        reply_text, patch = handle_flow(session, text)

        # if patch ends session, update accordingly
        if patch.get("status") in {"completed", "cancelled", "expired", "error"}:
            updated = update_session(session["id"], patch)
            session_id = updated["id"]
        else:
            # always refresh last_inbound + expiry
            patch.setdefault("last_inbound_at", now_utc().isoformat())
            patch.setdefault("expires_at", expires_at_utc(SESSION_TTL_MINUTES).isoformat())
            updated = update_session(session["id"], patch)
            session_id = updated["id"]

        # log outbound (note: actual sending to WhatsApp happens in your send-message function later)
        log_message(
            wa_phone=wa_phone,
            direction="outbound",
            text=reply_text,
            payload={"note": "reply_generated_locally"},
            session_id=session_id,
            message_id=None
        )

        # For now, return the reply as JSON (useful for testing)
        # In production, you'll call WhatsApp Cloud API to send message instead.
        return jsonify({"reply": reply_text}), 200

# ------------------------------------------------------------
# Entrypoint (Koyeb)
# ------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=False)
