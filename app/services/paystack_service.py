# app/services/paystack_service.py
from __future__ import annotations

import hmac
import hashlib
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
        "Accept": "application/json",
    }


def create_reference(prefix: str = "NTG") -> str:
    return f"{prefix}-{uuid4().hex}"


def initialize_transaction(
    *,
    email: str,
    amount_kobo: int,
    reference: str,
    currency: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    callback_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Initializes a Paystack transaction.

    IMPORTANT:
    - Paystack expects amount in KOBO (integer).
    - Use requests.post(..., json=payload) to ensure proper JSON body.
    """
    if not email:
        raise ValueError("missing_email")

    if amount_kobo is None:
        raise ValueError("missing_amount_kobo")

    try:
        amount_kobo_int = int(amount_kobo)
    except Exception:
        raise ValueError("invalid_amount_kobo")

    if amount_kobo_int <= 0:
        raise ValueError("invalid_amount_kobo")

    payload: Dict[str, Any] = {
        "email": email,
        "amount": amount_kobo_int,
        "currency": (currency or PAYSTACK_CURRENCY or "NGN").strip(),
        "reference": reference,
        "metadata": metadata or {},
    }

    cb = (callback_url or PAYSTACK_CALLBACK_URL or "").strip()
    if cb:
        payload["callback_url"] = cb

    r = requests.post(
        f"{PAYSTACK_BASE}/transaction/initialize",
        headers=_headers(),
        json=payload,
        timeout=25,
    )

    data = r.json() if r.content else {}
    if not r.ok or not data.get("status"):
        # Paystack returns: {status: false, message: "...", data: ...}
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
    Paystack webhook signature:
    HMAC SHA512 of the RAW request body, using secret key.
    Hex digest should match x-paystack-signature header.
    """
    if not PAYSTACK_SECRET_KEY:
        return False
    if not signature_header:
        return False

    mac = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        msg=raw_body or b"",
        digestmod=hashlib.sha512,
    ).hexdigest()

    return hmac.compare_digest(mac, signature_header.strip().lower())
