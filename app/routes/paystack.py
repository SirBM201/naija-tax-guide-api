from flask import Blueprint, request, jsonify
from ..services.db import supabase_admin
from ..services.paystack_service import paystack_init_transaction, PLAN_AMOUNTS_KOBO

bp = Blueprint("paystack", __name__)

@bp.post("/api/paystack/init")
def paystack_init():
    body = request.get_json(force=True) or {}

    account_id = (body.get("account_id") or "").strip()
    plan_code = (body.get("plan_code") or "").strip().lower()
    email = (body.get("email") or "").strip()
    callback_url = (body.get("callback_url") or "").strip()

    if not account_id:
        return jsonify({"ok": False, "error": "account_id is required"}), 400
    if plan_code not in PLAN_AMOUNTS_KOBO:
        return jsonify({"ok": False, "error": "Invalid plan_code"}), 400
    if not email or "@" not in email:
        return jsonify({"ok": False, "error": "Valid email is required"}), 400
    if not callback_url.startswith("http"):
        return jsonify({"ok": False, "error": "callback_url must be a valid URL"}), 400

    amount_kobo = PLAN_AMOUNTS_KOBO[plan_code]

    # IMPORTANT:
    # We save reference -> account_id + plan_code so webhook can activate correct subscription
    sb = supabase_admin()

    try:
        init = paystack_init_transaction(
            email=email,
            amount_kobo=amount_kobo,
            callback_url=callback_url,
            metadata={
                "account_id": account_id,
                "plan_code": plan_code,
                "product": "naija-tax-guide",
            },
        )

        reference = init["reference"]

        # Save mapping (create table 'paystack_refs' in Supabase)
        sb.table("paystack_refs").insert({
            "reference": reference,
            "account_id": account_id,
            "plan_code": plan_code,
            "status": "pending",
        }).execute()

        return jsonify({
            "ok": True,
            "reference": reference,
            "authorization_url": init["authorization_url"],
            "access_code": init["access_code"],
        })

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
