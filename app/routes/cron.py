import os
from flask import Blueprint, request, jsonify
from datetime import datetime, timezone

from app.db.supabase_client import supabase

bp = Blueprint("cron", __name__)

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()


def _auth_ok(req) -> bool:
    k = req.headers.get("x-admin-key", "") or ""
    return bool(ADMIN_API_KEY) and k == ADMIN_API_KEY


@bp.post("/cron/monthly-reset")
def monthly_reset():
    """
    Resets paid-plan AI credits monthly.
    Quarterly/Yearly users still keep rollover within validity because we set allowance by plan type.

    Strategy:
    - For each active user subscription:
        set ai_credits.remaining = allowance(plan)
    """
    if not _auth_ok(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    try:
        # get active subscriptions
        r = (
            supabase.table("user_subscriptions")
            .select("wa_phone,plan,status,expires_at")
            .eq("status", "active")
            .execute()
        )
        subs = r.data or []
    except Exception as e:
        return jsonify({"ok": False, "error": f"failed to read subscriptions: {e}"}), 500

    updated = 0
    now = datetime.now(timezone.utc).isoformat()

    for s in subs:
        wa_phone = s.get("wa_phone")
        plan = (s.get("plan") or "").lower()
        expires_at = s.get("expires_at")

        if plan not in ("monthly", "quarterly", "yearly"):
            continue

        allowance = 300 * (3 if plan == "quarterly" else 12 if plan == "yearly" else 1)

        try:
            supabase.table("ai_credits").upsert(
                {
                    "wa_phone": wa_phone,
                    "plan": plan,
                    "remaining": allowance,
                    "expires_at": expires_at,
                    "updated_at": now,
                },
                on_conflict="wa_phone",
            ).execute()
            updated += 1
        except Exception:
            continue

    return jsonify({"ok": True, "updated": updated})
