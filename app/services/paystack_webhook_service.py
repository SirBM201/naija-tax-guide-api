# app/services/paystack_webhook_service.py
from __future__ import annotations

import os
import json
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from ..core.supabase_client import supabase


PAYSTACK_SECRET_KEY = (os.getenv("PAYSTACK_SECRET_KEY", "") or "").strip()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _verify_paystack_signature(raw_body: bytes, signature: str) -> bool:
    """
    Paystack signature:
      HMAC-SHA512(secret_key, raw_request_body) hex digest
    Header name: x-paystack-signature
    """
    if not PAYSTACK_SECRET_KEY or not signature:
        return False
    digest = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        raw_body,
        hashlib.sha512,
    ).hexdigest()
    return hmac.compare_digest(digest, signature.strip())


def _safe_json_loads(raw_body: bytes) -> Dict[str, Any]:
    try:
        return json.loads(raw_body.decode("utf-8"))
    except Exception:
        return {}


def _extract_meta(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Paystack typically puts custom metadata at:
      data.metadata (dict)
    """
    meta = data.get("metadata")
    return meta if isinstance(meta, dict) else {}


def _get_nested(d: Dict[str, Any], *path: str) -> Optional[Any]:
    cur: Any = d
    for k in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def _normalize_plan_code(plan_code: Optional[str]) -> Optional[str]:
    if not plan_code:
        return None
    return plan_code.strip().lower() or None


def _try_lookup_account_id_by_wa_phone(wa_phone: Optional[str]) -> Optional[str]:
    """
    Best-effort fallback.
    If you have an accounts table with wa_phone/phone, this will find it.
    If your schema differs, it will fail silently and return None.
    """
    if not wa_phone:
        return None
    try:
        db = supabase()
        # Try common patterns: accounts.wa_phone OR accounts.phone
        res = (
            db.table("accounts")
            .select("id")
            .or_(f"wa_phone.eq.{wa_phone},phone.eq.{wa_phone}")
            .limit(1)
            .execute()
        )
        if res.data:
            return res.data[0].get("id")
    except Exception:
        pass
    return None


def _upsert_paystack_payments(reference: str, payload: Dict[str, Any], meta: Dict[str, Any]) -> None:
    """
    Upsert into public.paystack_payments (PK = reference).
    Columns per your JSON:
      reference, wa_phone, email, plan, amount_kobo, currency, status,
      gateway_response, raw, created_at, updated_at
    """
    data = payload.get("data") or {}
    customer_email = _get_nested(data, "customer", "email") or meta.get("email") or None
    wa_phone = meta.get("wa_phone") or meta.get("phone") or None
    plan = meta.get("plan") or meta.get("plan_code") or None

    row = {
        "reference": reference,
        "wa_phone": wa_phone,
        "email": customer_email,
        "plan": plan,
        "amount_kobo": data.get("amount"),
        "currency": data.get("currency"),
        "status": data.get("status"),
        "gateway_response": data.get("gateway_response"),
        "raw": payload,
        "updated_at": _now_utc().isoformat(),
    }

    db = supabase()
    db.table("paystack_payments").upsert(row, on_conflict="reference").execute()


def _upsert_payments(reference: str, payload: Dict[str, Any], meta: Dict[str, Any], account_id: Optional[str]) -> None:
    """
    Upsert into public.payments (PK = reference).
    Columns per your JSON:
      reference, wa_phone, provider, plan, amount_kobo, currency, status,
      created_at, paid_at, raw_event, email, amount(numeric), account_id(uuid),
      provider_ref, raw, updated_at, plan_code
    """
    data = payload.get("data") or {}
    event = (payload.get("event") or "").strip()

    wa_phone = meta.get("wa_phone") or meta.get("phone") or (data.get("customer") or {}).get("phone") or None
    email = (data.get("customer") or {}).get("email") or meta.get("email") or None

    plan_code = _normalize_plan_code(meta.get("plan_code") or meta.get("plan") or None)

    row = {
        "reference": reference,
        "wa_phone": wa_phone or "",
        "provider": "paystack",
        "plan": (meta.get("plan") or plan_code or "") if (meta.get("plan") or plan_code) else "",
        "amount_kobo": int(data.get("amount") or 0),
        "currency": (data.get("currency") or "NGN"),
        "status": (data.get("status") or "unknown"),
        "paid_at": data.get("paid_at"),
        "raw_event": payload,
        "email": email,
        "amount": None,  # optional numeric column; you can compute later if you want
        "account_id": account_id,
        "provider_ref": reference,
        "raw": payload,
        "updated_at": _now_utc().isoformat(),
        "plan_code": plan_code,
    }

    db = supabase()
    db.table("payments").upsert(row, on_conflict="reference").execute()


def _attempt_fulfill(reference: str, account_id: Optional[str]) -> Dict[str, Any]:
    """
    Calls public.fulfill_payment(reference, account_id).
    This function must exist already (you ran the SQL).
    """
    if not account_id:
        return {"ok": False, "reason": "missing_account_id_for_fulfillment"}

    try:
        res = supabase().rpc("fulfill_payment", {"p_reference": reference, "p_account_id": account_id}).execute()
        data = res.data
        if isinstance(data, list):
            data = data[0] if data else {}
        if isinstance(data, dict) and data.get("ok"):
            return {"ok": True, "fulfill": data}
        return {"ok": False, "reason": "fulfill_failed", "fulfill": data}
    except Exception as e:
        return {"ok": False, "reason": "fulfill_exception", "message": str(e)}


def handle_paystack_webhook(raw_body: bytes, headers: Dict[str, str]) -> Dict[str, Any]:
    signature = headers.get("x-paystack-signature") or headers.get("X-Paystack-Signature")

    # 1) Verify signature
    if not _verify_paystack_signature(raw_body, signature or ""):
        return {
            "ok": False,
            "reason": "invalid_signature",
            "http_status": 401,
        }

    payload = _safe_json_loads(raw_body)
    event = (payload.get("event") or "").strip()
    data = payload.get("data") or {}

    reference = (data.get("reference") or "").strip()
    if not reference:
        return {"ok": False, "reason": "missing_reference", "http_status": 400}

    meta = _extract_meta(data)

    # For strongest mapping: include metadata.account_id at payment init
    account_id = meta.get("account_id") or None
    if account_id:
        account_id = str(account_id).strip() or None

    # Fallback mapping: metadata.wa_phone
    if not account_id:
        wa_phone = meta.get("wa_phone") or meta.get("phone") or None
        account_id = _try_lookup_account_id_by_wa_phone(wa_phone)

    # 2) Upsert raw tables first (idempotent)
    try:
        _upsert_paystack_payments(reference, payload, meta)
    except Exception:
        # If this fails, return 500 so Paystack retries
        return {"ok": False, "reason": "db_error_paystack_payments", "http_status": 500}

    try:
        _upsert_payments(reference, payload, meta, account_id)
    except Exception:
        return {"ok": False, "reason": "db_error_payments", "http_status": 500}

    # 3) Fulfill only for success events
    # Paystack success is typically: "charge.success"
    if event == "charge.success" and (data.get("status") == "success"):
        fulfill = _attempt_fulfill(reference, account_id)
        return {
            "ok": True,
            "event": event,
            "reference": reference,
            "account_id": account_id,
            "fulfilled": bool(fulfill.get("ok")),
            "fulfill_result": fulfill,
        }

    # For non-success events, store only
    return {
        "ok": True,
        "event": event,
        "reference": reference,
        "account_id": account_id,
        "fulfilled": False,
        "note": "stored_event_only",
    }
