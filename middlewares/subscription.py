from datetime import datetime, timezone
from flask import jsonify
from supabase import create_client
import os

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

def require_active_subscription(wa_phone: str):
    """
    Enforces subscription before allowing message processing.
    Returns (allowed: bool, response_json, status_code)
    """

    if not wa_phone:
        return False, jsonify({
            "ok": False,
            "error": "missing_whatsapp_number"
        }), 400

    sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

    res = (
        sb.table("user_subscriptions")
        .select("status, expires_at, plan")
        .eq("wa_phone", wa_phone)
        .single()
        .execute()
    )

    if not res.data:
        return False, jsonify({
            "ok": False,
            "error": "subscription_required",
            "message": "No active subscription found. Please subscribe."
        }), 403

    status = res.data["status"]
    expires_at = res.data["expires_at"]

    now = datetime.now(timezone.utc)

    if status != "active":
        return False, jsonify({
            "ok": False,
            "error": "subscription_inactive",
            "message": "Subscription inactive. Please renew."
        }), 403

    if expires_at and expires_at < now.isoformat():
        # Auto-expire defensively
        sb.table("user_subscriptions").update({
            "status": "expired"
        }).eq("wa_phone", wa_phone).execute()

        return False, jsonify({
            "ok": False,
            "error": "subscription_expired",
            "message": "Subscription expired. Please renew."
        }), 403

    # ✅ Allowed
    return True, None, None
