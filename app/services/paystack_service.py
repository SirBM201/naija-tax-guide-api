# app/services/paystack_service.py
from __future__ import annotations

import hmac
import hashlib
import json
from typing import Any, Dict
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
    amount_naira: int | None = None,
    amount_kobo: int | None = None,
    reference: str,
    metadata: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """
    Paystack expects amount in KOBO.

    - If amount_kobo is provided, use it as-is.
    - Else if amount_naira is provided, multiply by 100.
    """
    if not email:
        raise ValueError("missing_email")
    if not reference:
        raise ValueError("missing_reference")

    if amount_kobo is not None:
        amt = int(amount_kobo)
    elif amount_naira is not None:
        amt = int(amount_naira) * 100
    else:
        raise ValueError("missing_amount")

    if amt <= 0:
        raise ValueError("invalid_amount")

    payload: Dict[str, Any] = {
        "email": email,
        "amount": amt,
        "currency": PAYSTACK_CURRENCY or "NGN",
        "reference": reference,
        "metadata": metadata or {},
    }

    if PAYSTACK_CALLBACK_URL:
        payload["callback_url"] = PAYSTACK_CALLBACK_URL

    r = requests.post(
        f"{PAYSTACK_BASE}/transaction/initialize",
        headers=_headers(),
        data=json.dumps(payload),
        timeout=25,
    )

    data = r.json() if r.content else {}
    if not r.ok or not data.get("status"):
        msg = data.get("message") or f"paystack_init_failed_http_{r.status_code}"
        raise RuntimeError(msg)

    return data


def verify_transaction(reference: str) -> Dict[str, Any]:
    if not reference:
        raise ValueError("missing_reference")

    r = requests.get(
        f"{PAYSTACK_BASE}/transaction/verify/{reference}",
        headers=_headers(),
        timeout=25,
    )
    data = r.json() if r.content else {}
    if not r.ok or not data.get("status"):
        msg = data.get("message") or f"paystack_verify_failed_http_{r.status_code}"
        raise RuntimeError(msg)
    return data


def verify_webhook_signature(raw_body: bytes, signature_header: str) -> bool:
    if not PAYSTACK_SECRET_KEY:
        return False
    if not signature_header:
        return False
    mac = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha512,
    ).hexdigest()
    return hmac.compare_digest(mac, signature_header)


def health() -> Dict[str, Any]:
    # simple sanity helper (does NOT call paystack)
    return {
        "ok": True,
        "paystack_base": PAYSTACK_BASE,
        "currency": PAYSTACK_CURRENCY or "NGN",
        "callback_url_set": bool(PAYSTACK_CALLBACK_URL),
        "secret_key_set": bool(PAYSTACK_SECRET_KEY),
    }
