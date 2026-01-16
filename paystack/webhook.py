# paystack/webhook.py
import os
import json
import hmac
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

from flask import Blueprint, request, jsonify
from supabase import create_client

bp = Blueprint("paystack_webhook", __name__)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY).strip()

DEFAULT_PLAN_DURATION_DAYS = int(os.getenv("DEFAULT_PLAN_DURATION_DAYS", "30"))

_supabase = None

def sb():
    global _supabase
    if _supabase is None:
        if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
            raise RuntimeError("SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY not set")
        _supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    return _supabase

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def plan_to_days(plan: str) -> int:
    p = (plan or "").lower().strip()
    if p in ("monthly", "month", "m"):
        return 30
    if p in ("quarterly", "quarter", "q"):
        return 90
    if p in ("yearly", "year", "annual", "y"):
        return 365
    return DEFAULT_PLAN_DURATION_DAYS

def verify_signature(raw_body: bytes, signature: str) -> bool:
    secret = PAYSTACK_WEBHOOK_SECRET or PAYSTACK_SECRET_KEY
    if not secret:
        return False
    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha512).hexdigest()
    return hmac.compare_digest(expected, signature or "")

def activate_user_subscription(wa_phone: str, plan: str, reference: Optional[str], last_event: str) -> None:
    expires_at = iso(now_utc() + timedelta(days=plan_to_days(plan)))
    sb().table("user_subscriptions").upsert({
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "active",
        "expires_at": expires_at,
        "paystack_reference": reference,
        "last_event": last_event,
        "updated_at": iso(now_utc()),
    }, on_conflict="wa_phone").execute()

def mark_subscription_inactive(wa_phone: str, plan: Optional[str], last_event: str) -> None:
    payload = {
        "wa_phone": wa_phone,
        "status": "inactive",
        "last_event": last_event,
        "updated_at": iso(now_utc()),
    }
    if plan:
        payload["plan"] = plan
    sb().table("user_subscriptions").upsert(payload, on_conflict="wa_phone").execute()

def store_event(event_id: str, event_name: str, reference: Optional[str], wa_phone: Optional[str], raw: Dict[str, Any]) -> None:
    # Safe if table exists; if not, we skip without crashing webhook.
    try:
        sb().table("paystack_events").upsert({
            "event_id": event_id,
            "event": event_name,
            "reference": reference,
            "wa_phone": wa_phone,
            "raw_event": raw,
            "created_at": iso(now_utc()),
        }, on_conflict="event_id").execute()
    except Exception as e:
        logging.warning("paystack_events write skipped/failed: %s", str(e))

@bp.post("/webhooks/paystack")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if not (PAYSTACK_SECRET_KEY or PAYSTACK_WEBHOOK_SECRET):
        return "PAYSTACK_SECRET_KEY not set", 500

    if not verify_signature(raw, sig):
        logging.warning("Paystack webhook: invalid signature")
        return "invalid signature", 401

    try:
        event = json.loads(raw.decode("utf-8"))
    except Exception:
        logging.exception("Paystack webhook: invalid JSON")
        return "invalid json", 400

    event_name = (event.get("event") or "").strip()
    data = event.get("data") or {}

    reference = (data.get("reference") or "").strip() or None
    event_id = str(data.get("id") or reference or f"evt_{int(now_utc().timestamp())}")

    metadata = data.get("metadata") or {}
    wa_phone = (metadata.get("wa_phone") or "").strip() or None
    plan = (metadata.get("plan") or "").strip() or None
    purpose = (metadata.get("purpose") or "").strip() or None

    status = (data.get("status") or "").strip().lower()

    # store event (idempotent)
    store_event(event_id, event_name, reference, wa_phone, event)

    # business logic
    try:
        if event_name == "charge.success" and status == "success":
            if purpose == "subscription" and wa_phone and plan:
                activate_user_subscription(wa_phone, plan, reference, event_name)
                logging.info("Subscription activated for %s (%s)", wa_phone, plan)

        elif event_name.startswith("refund"):
            if purpose == "subscription" and wa_phone:
                mark_subscription_inactive(wa_phone, plan, event_name)
                logging.info("Refund processed; subscription inactivated for %s", wa_phone)

    except Exception:
        logging.exception("Paystack webhook business logic error")

    return "ok", 200
