# app/services/paystack_service.py
from __future__ import annotations

import hmac
import hashlib
import json
from typing import Any, Dict, Optional
from uuid import uuid4

import requests

from app.core.config import PAYSTACK_SECRET_KEY, PAYSTACK_CURRENCY, PAYSTACK_CALLBACK_URL

PAYSTACK_BASE = "https://api.paystack.co"


def _headers() -> Dict[str, str]:
    if not PAYSTACK_SECRET_KEY:
        raise RuntimeError("PAYSTACK_SECRET_KEY not configured")
    return {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }


def create_reference(prefix: str = "NTG") -> str:
    return f"{prefix}-{uuid4().hex}"


def initialize_transaction(
    *,
    email: str,
    amount_kobo: int,
    reference: str,
    metadata: Optional[Dict[str, Any]] = None,
    currency: Optional[str] = None,
    callback_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Paystack expects amount in KOBO.
    Returns Paystack JSON response: { status: bool, message: str, data: {...} }
    """
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("missing_email")

    kobo = int(amount_kobo or 0)
    if kobo <= 0:
        raise ValueError("invalid_amount_kobo")

    ref = (reference or "").strip()
    if not ref:
        raise ValueError("missing_reference")

    payload: Dict[str, Any] = {
        "email": email,
        "amount": kobo,
        "currency": (currency or PAYSTACK_CURRENCY or "NGN"),
        "reference": ref,
        "metadata": metadata or {},
    }

    cb = (callback_url or PAYSTACK_CALLBACK_URL or "").strip()
    if cb:
        payload["callback_url"] = cb

    r = requests.post(
        f"{PAYSTACK_BASE}/transaction/initialize",
        headers=_headers(),
        data=json.dumps(payload),
        timeout=25,
    )

    data = r.json() if r.content else {}
    if not r.ok or not data.get("status"):
        raise RuntimeError(data.get("message") or "paystack_init_failed")

    return data


def verify_transaction(reference: str) -> Dict[str, Any]:
    reference = (reference or "").strip()
    if not reference:
        raise ValueError("missing_reference")

    r = requests.get(
        f"{PAYSTACK_BASE}/transaction/verify/{reference}",
        headers=_headers(),
        timeout=25,
    )

    data = r.json() if r.content else {}
    if not r.ok or not data.get("status"):
        raise RuntimeError(data.get("message") or "paystack_verify_failed")
    return data


def verify_webhook_signature(raw_body: bytes, signature_header: str) -> bool:
    """
    Paystack sends: x-paystack-signature = HMAC_SHA512(raw_body, secret_key)
    """
    sig = (signature_header or "").strip()
    if not PAYSTACK_SECRET_KEY or not sig:
        return False

    mac = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha512,
    ).hexdigest()

    return hmac.compare_digest(mac, sig)
