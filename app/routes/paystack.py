# app/routes/paystack.py
from __future__ import annotations

import os
import uuid
import requests
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify
from app.core.supabase_client import supabase

paystack_bp = Blueprint("paystack", __name__)

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_CALLBACK_URL = os.getenv("PAYSTACK_CALLBACK_URL", "").strip()

PLAN_PRICES = {"monthly": 330000, "quarterly": 900000, "yearly": 3300000}  # KOBO

PAYSTACK_INIT_URL = "https://api.paystack.co/transaction/initialize"
PAYSTACK_VERIFY_URL = "https://api.paystack.co/transaction/verify/"


def _headers() -> dict:
    return {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}", "Content-Type": "application/json"}


def _normalize_upgrade_mode(v: str) -> str:
    m = (v or "now").strip().lower()
    return m if m in ("now", "at_expiry") else "now"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@paystack_bp.post("/paystack/init")
def init_payment():
    """
    Body:
      {
        "account_id": "<uuid>",
        "wa_phone": "<string>",
        "email": "<email>",
        "plan_code": "monthly|quarterly|yearly",
        "upgrade_mode": "now|at_expiry" (optional)
      }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not configured"}), 500

    data = request.get_json(silent=True) or {}
    account_id = (data.get("account_id") or "").strip()
    wa_phone = (data.get("wa_phone") or "").strip()
    email = (data.get("email") or "").strip()
    plan_code = (data.get("plan_code") or "").strip().lower()
    upgrade_mode = _normalize_upgrade_mode(data.get("upgrade_mode") or "now")

    if not account_id or not wa_phone or not email or not plan_code:
        return jsonify({"ok": False, "error": "Missing required fields: account_id, wa_phone, email, plan_code"}), 400

    if plan_code not in PLAN_PRICES:
        return jsonify({"ok": False, "error": "Invalid plan_code"}), 400

    reference = f"NTG-{uuid.uuid4()}"
    amount = int(PLAN_PRICES[plan_code])
    now_iso = _now_iso()

    payload = {
        "email": email,
        "amount": amount,
        "reference": reference,
        "metadata": {
            "account_id": account_id,
            "wa_phone": wa_phone,
            "plan_code": plan_code,
            "upgrade_mode": upgrade_mode,
        },
    }
    if PAYSTACK_CALLBACK_URL:
        payload["callback_url"] = PAYSTACK_CALLBACK_URL

    try:
        resp = requests.post(PAYSTACK_INIT_URL, json=payload, headers=_headers(), timeout=20)
        pdata = resp.json()
    except Exception as e:
        return jsonify({"ok": False, "error": f"Paystack init failed: {str(e)}"}), 502

    if not pdata.get("status"):
        return jsonify({"ok": False, "error": "Paystack init failed", "paystack": pdata}), 400

    auth_url = (pdata.get("data") or {}).get("authorization_url")
    if not auth_url:
        return jsonify({"ok": False, "error": "Paystack init missing authorization_url", "paystack": pdata}), 502

    sb = supabase()

    # best-effort mirrors
    try:
        sb.table("paystack_payments").upsert(
            {
                "reference": reference,
                "wa_phone": wa_phone,
                "email": email,
                "plan": plan_code,
                "amount_kobo": amount,
                "currency": "NGN",
                "status": "pending",
                "raw": pdata,
                "updated_at": now_iso,
            },
            on_conflict="reference",
        ).execute()
    except Exception:
        pass

    try:
        sb.table("payments").upsert(
            {
                "reference": reference,
                "wa_phone": wa_phone,
                "provider": "paystack",
                "plan": plan_code,
                "amount_kobo": amount,
                "currency": "NGN",
                "status": "pending",
                "created_at": now_iso,
                "updated_at": now_iso,
                "raw": pdata,
                "raw_event": None,
                "email": email,
                "account_id": account_id,
                "provider_ref": None,
                "plan_code": plan_code,
            },
            on_conflict="reference",
        ).execute()
    except Exception:
        pass

    return jsonify({"ok": True, "authorization_url": auth_url, "reference": reference}), 200


@paystack_bp.get("/paystack/verify/<reference>")
def verify_payment(reference: str):
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not configured"}), 500

    reference = (reference or "").strip()
    if not reference:
        return jsonify({"ok": False, "error": "reference is required"}), 400

    try:
        resp = requests.get(f"{PAYSTACK_VERIFY_URL}{reference}", headers=_headers(), timeout=20)
        pdata = resp.json()
    except Exception as e:
        return jsonify({"ok": False, "error": f"Paystack verify failed: {str(e)}"}), 502

    if not pdata.get("status"):
        return jsonify({"ok": False, "error": "Paystack verify returned failure", "paystack": pdata}), 400

    data = pdata.get("data") or {}
    paid = (data.get("status") or "").lower() == "success"
    now_iso = _now_iso()

    try:
        supabase().table("paystack_payments").update(
            {
                "status": "success" if paid else (data.get("status") or "unknown"),
                "gateway_response": data.get("gateway_response"),
                "raw": pdata,
                "updated_at": now_iso,
            }
        ).eq("reference", reference).execute()
    except Exception:
        pass

    try:
        supabase().table("payments").update(
            {"status": "success" if paid else (data.get("status") or "unknown"), "raw": pdata, "updated_at": now_iso}
        ).eq("reference", reference).execute()
    except Exception:
        pass

    return jsonify({"ok": True, "paid": paid, "paystack_status": data.get("status"), "reference": reference}), 200
