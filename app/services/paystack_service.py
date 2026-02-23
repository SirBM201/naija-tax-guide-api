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
    reference: Optional[str] = None,
    currency: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Initializes a Paystack transaction.

    IMPORTANT:
    - Paystack expects amount in KOBO (NGN), so caller must pass kobo.
    - reference is optional; if missing, we'll generate one.
    """
    email = (email or "").strip()
    if not email:
        raise ValueError("missing_email")

    try:
        amount_kobo_int = int(amount_kobo)
    except Exception:
        raise ValueError("invalid_amount_kobo")

    if amount_kobo_int <= 0:
        raise ValueError("invalid_amount_kobo")

    ref = (reference or "").strip() or create_reference("NTG")
    cur = (currency or PAYSTACK_CURRENCY or "NGN").strip() or "NGN"

    payload: Dict[str, Any] = {
        "email": email,
        "amount": amount_kobo_int,  # KOBO
        "currency": cur,
        "reference": ref,
        "metadata": metadata or {},
    }

    if PAYSTACK_CALLBACK_URL:
        payload["callback_url"] = PAYSTACK_CALLBACK_URL

    r = requests.post(
        f"{PAYSTACK_BASE}/transaction/initialize",
        headers=_headers(),
        json=payload,
        timeout=25,
    )

    # Paystack almost always returns JSON; still guard safely.
    data: Dict[str, Any] = {}
    try:
        data = r.json() if r.content else {}
    except Exception:
        data = {}

    # Paystack success shape: { "status": true, "message": "...", "data": {...} }
    if (not r.ok) or (not data.get("status")):
        msg = data.get("message") or f"paystack_init_failed_http_{r.status_code}"
        raise RuntimeError(msg)

    # Ensure our reference is returned even if Paystack doesn't echo (it should)
    if isinstance(data.get("data"), dict) and not data["data"].get("reference"):
        data["data"]["reference"] = ref

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

    data: Dict[str, Any] = {}
    try:
        data = r.json() if r.content else {}
    except Exception:
        data = {}

    if (not r.ok) or (not data.get("status")):
        msg = data.get("message") or f"paystack_verify_failed_http_{r.status_code}"
        raise RuntimeError(msg)

    return data


def verify_webhook_signature(raw_body: bytes, signature_header: str) -> bool:
    """
    Paystack webhook signature uses HMAC SHA512(secret_key, raw_body)
    Header: x-paystack-signature: <hex digest>
    """
    if not PAYSTACK_SECRET_KEY:
        return False

    sig = (signature_header or "").strip()
    if not sig:
        return False

    mac = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha512,
    ).hexdigest()

    return hmac.compare_digest(mac, sig)
