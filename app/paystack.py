import hmac
import hashlib
import requests
from datetime import datetime, timedelta, timezone
from flask import request, jsonify

from .config import settings
from .supabase_db import get_supabase

PAYSTACK_BASE = "https://api.paystack.co"

def plan_to_amount_kobo(plan: str) -> int:
    plan = plan.lower().strip()
    if plan == "monthly":
        return 3000 * 100
    if plan == "quarterly":
        return 8000 * 100
    if plan == "yearly":
        return 30000 * 100
    raise ValueError("Invalid plan")

def plan_to_duration_days(plan: str) -> int:
    plan = plan.lower().strip()
    if plan == "monthly":
        return 30
    if plan == "quarterly":
        return 90
    if plan == "yearly":
        return 365
    raise ValueError("Invalid plan")

@app.post("/paystack/initialize")
def paystack_initialize():
    """
    Body:
    {
      "wa_phone": "23480....",
      "plan": "monthly|quarterly|yearly",
      "email": "customer@email.com"
    }
    """
    data = request.get_json(silent=True) or {}
    wa_phone = (data.get("wa_phone") or "").strip()
    plan = (data.get("plan") or "").strip().lower()
    email = (data.get("email") or "").strip()

    if not wa_phone or plan not in ("monthly","quarterly","yearly") or not email:
        return jsonify({"error": "wa_phone, plan, email required"}), 400

    amount_kobo = plan_to_amount_kobo(plan)

    headers = {
        "Authorization": f"Bearer {os.getenv('PAYSTACK_SECRET_KEY','')}",
        "Content-Type": "application/json",
    }
    if not headers["Authorization"].endswith(" "):  # simple check
        pass

    # Ensure user exists
    sb = get_supabase()
    ures = sb.table("users").select("*").eq("wa_phone", wa_phone).limit(1).execute()
    user = (ures.data or [None])[0]
    if not user:
        ins = sb.table("users").insert({"wa_phone": wa_phone, "state": "idle"}).execute()
        user = (ins.data or [None])[0]

    payload = {
        "email": email,
        "amount": amount_kobo,
        "currency": "NGN",
        "callback_url": os.getenv("PAYSTACK_CALLBACK_URL", ""),
        "metadata": {"wa_phone": wa_phone, "plan": plan, "user_id": user["id"]},
    }

    r = requests.post(f"{PAYSTACK_BASE}/transaction/initialize", headers=headers, json=payload, timeout=30)
    if not r.ok:
        return jsonify({"error": "paystack init failed", "details": r.text}), 400

    res = r.json()
    ref = res["data"]["reference"]
    auth_url = res["data"]["authorization_url"]

    # Save payment init
    sb.table("payments").insert({
        "user_id": user["id"],
        "reference": ref,
        "amount_kobo": amount_kobo,
        "currency": "NGN",
        "status": "initialized",
        "raw_payload": res,
    }).execute()

    return jsonify({"authorization_url": auth_url, "reference": ref}), 200


@app.post("/paystack/webhook")
def paystack_webhook():
    """
    Paystack sends event here.
    Must verify signature via x-paystack-signature.
    """
    secret = os.getenv("PAYSTACK_SECRET_KEY", "")
    signature = request.headers.get("x-paystack-signature", "")
    body = request.get_data()  # raw bytes

    if not secret:
        return jsonify({"error": "PAYSTACK_SECRET_KEY missing"}), 500

    computed = hmac.new(secret.encode("utf-8"), body, hashlib.sha512).hexdigest()
    if computed != signature:
        return jsonify({"error": "invalid signature"}), 401

    event = request.get_json(silent=True) or {}
    event_type = event.get("event", "")
    data = event.get("data", {}) or {}
    reference = data.get("reference")

    sb = get_supabase()

    # Update payment record
    if reference:
        sb.table("payments").update({
            "status": "success" if event_type == "charge.success" else "failed",
            "raw_payload": event,
        }).eq("reference", reference).execute()

    # On success, activate subscription
    if event_type == "charge.success":
        meta = data.get("metadata") or {}
        plan = (meta.get("plan") or "").lower()
        user_id = meta.get("user_id")
        if user_id and plan in ("monthly","quarterly","yearly"):
            start_at = datetime.now(timezone.utc)
            end_at = start_at + timedelta(days=plan_to_duration_days(plan))

            # Upsert subscription (1 row per user)
            sb.table("subscriptions").upsert({
                "user_id": user_id,
                "plan": plan,
                "status": "active",
                "start_at": start_at.isoformat(),
                "end_at": end_at.isoformat(),
                "paystack_ref": reference,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }, on_conflict="user_id").execute()

    return jsonify({"ok": True}), 200
