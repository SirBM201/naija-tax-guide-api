import os
import requests
from flask import Blueprint, request, jsonify

paystack_verify_bp = Blueprint("paystack_verify_bp", __name__)

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")
PAYSTACK_API = "https://api.paystack.co"

# You already use something like this in your project
def activate_user_subscription(wa_phone: str, plan: str) -> None:
    # IMPORTANT: replace this with YOUR existing activation logic
    # (the one you posted earlier using Supabase upsert)
    from app import activate_user_subscription as _activate
    _activate(wa_phone, plan)

@paystack_verify_bp.post("/verify")
def paystack_verify():
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500

    body = request.get_json(silent=True) or {}
    reference = str(body.get("reference", "")).strip()
    if not reference:
        return jsonify({"ok": False, "error": "reference required"}), 400

    r = requests.get(
        f"{PAYSTACK_API}/transaction/verify/{reference}",
        headers={"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"},
        timeout=30,
    )

    data = r.json() if r.content else {}
    if r.status_code != 200:
        return jsonify({"ok": False, "error": "paystack_verify_failed", "detail": data}), 502

    d = data.get("data") or {}
    paid = (d.get("status") == "success")

    # Try to extract metadata so we can activate subscription
    meta = d.get("metadata") or {}
    wa_phone = str(meta.get("wa_phone") or "").strip()
    plan = str(meta.get("plan") or "").strip().lower()

    if paid:
        if wa_phone and plan:
            activate_user_subscription(wa_phone, plan)
        return jsonify({"ok": True, "paid": True, "reference": reference}), 200

    return jsonify({"ok": True, "paid": False, "reference": reference, "status": d.get("status")}), 200
