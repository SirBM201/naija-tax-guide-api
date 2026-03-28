from __future__ import annotations

import hmac
import hashlib
import json
import os
from typing import Any, Dict, Optional
from urllib.parse import urlencode
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


def _safe_excerpt(obj: Any, limit: int = 1200) -> str:
    try:
        s = json.dumps(obj, ensure_ascii=False, default=str)
    except Exception:
        s = str(obj)
    return s if len(s) <= limit else (s[:limit] + "...<truncated>")


def _clean(value: Any) -> str:
    return str(value or "").strip()


def create_reference(prefix: str = "NTG") -> str:
    return f"{prefix}-{uuid4().hex}"


def _public_base_url() -> str:
    """
    Best-effort public backend base URL for channel-aware return routes.
    Preference order:
    1) PAYSTACK_CHANNEL_CALLBACK_URL base (if supplied directly, we use it elsewhere)
    2) PUBLIC_BACKEND_BASE_URL
    3) BACKEND_PUBLIC_URL
    4) APP_BASE_URL
    5) KOYEB_PUBLIC_DOMAIN
    6) PAYSTACK_CALLBACK_URL parent base
    """
    explicit = _clean(os.getenv("PAYSTACK_CHANNEL_CALLBACK_URL"))
    if explicit:
        return explicit.rstrip("/")

    candidates = [
        os.getenv("PUBLIC_BACKEND_BASE_URL"),
        os.getenv("BACKEND_PUBLIC_URL"),
        os.getenv("APP_BASE_URL"),
        os.getenv("KOYEB_PUBLIC_DOMAIN"),
    ]
    for item in candidates:
        value = _clean(item)
        if value:
            if value.startswith("http://") or value.startswith("https://"):
                return value.rstrip("/")
            return f"https://{value.rstrip('/')}"

    fallback = _clean(PAYSTACK_CALLBACK_URL)
    if fallback:
        lowered = fallback.lower()
        markers = ["/billing/verify", "/api/billing/verify", "/billing/success", "/api/billing/success"]
        for marker in markers:
            idx = lowered.find(marker)
            if idx > 0:
                return fallback[:idx].rstrip("/")

    return ""


def _build_channel_callback_url(
    *,
    reference: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Build a channel-aware callback URL when metadata indicates Telegram/WhatsApp checkout.
    Optional env:
    - PAYSTACK_CHANNEL_CALLBACK_URL
    - PUBLIC_BACKEND_BASE_URL
    - BACKEND_PUBLIC_URL
    - APP_BASE_URL
    - KOYEB_PUBLIC_DOMAIN
    """
    md = metadata if isinstance(metadata, dict) else {}
    channel_type = _clean(md.get("channel_type")).lower()
    provider_user_id = _clean(md.get("provider_user_id"))
    account_id = _clean(md.get("account_id"))
    plan_code = _clean(md.get("plan_code"))

    if channel_type not in {"telegram", "whatsapp"}:
        return ""

    explicit = _clean(os.getenv("PAYSTACK_CHANNEL_CALLBACK_URL"))
    if explicit:
        base = explicit.rstrip("/")
    else:
        root = _public_base_url()
        if not root:
            return ""
        base = f"{root}/api/channel/payment/return"

    qs = urlencode(
        {
            "reference": reference,
            "channel_type": channel_type,
            "provider_user_id": provider_user_id,
            "account_id": account_id,
            "plan_code": plan_code,
        }
    )
    return f"{base}?{qs}"


def initialize_transaction(
    *,
    email: str,
    amount_kobo: int,
    reference: str,
    metadata: Optional[Dict[str, Any]] = None,
    currency: Optional[str] = None,
    callback_url: Optional[str] = None,
) -> Dict[str, Any]:
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("missing_email")

    ref = (reference or "").strip()
    if not ref:
        raise ValueError("missing_reference")

    kobo = int(amount_kobo or 0)
    if kobo <= 0:
        raise ValueError("invalid_amount_kobo")

    md = metadata or {}

    payload: Dict[str, Any] = {
        "email": email,
        "amount": kobo,
        "currency": (currency or PAYSTACK_CURRENCY or "NGN"),
        "reference": ref,
        "metadata": md,
    }

    cb = _clean(callback_url)
    if not cb:
        cb = _build_channel_callback_url(reference=ref, metadata=md)
    if not cb:
        cb = _clean(PAYSTACK_CALLBACK_URL)

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
        msg = data.get("message") or "paystack_init_failed"
        raise RuntimeError(f"{msg} | http={r.status_code} | body={_safe_excerpt(data)}")

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
        msg = data.get("message") or "paystack_verify_failed"
        raise RuntimeError(f"{msg} | http={r.status_code} | body={_safe_excerpt(data)}")

    return data


def verify_webhook_signature(raw_body: bytes, signature_header: str) -> bool:
    sig = (signature_header or "").strip()
    if not PAYSTACK_SECRET_KEY or not sig:
        return False

    mac = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha512,
    ).hexdigest()

    return hmac.compare_digest(mac, sig)
