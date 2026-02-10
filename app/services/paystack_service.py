# app/services/paystack_service.py
from __future__ import annotations

import os
import requests

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_BASE = "https://api.paystack.co"


def verify_transaction(reference: str) -> dict:
    if not PAYSTACK_SECRET_KEY:
        raise RuntimeError("PAYSTACK_SECRET_KEY is not set")

    reference = (reference or "").strip()
    if not reference:
        raise RuntimeError("reference is required")

    url = f"{PAYSTACK_BASE}/transaction/verify/{reference}"
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}

    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Paystack verify failed: {r.status_code} {r.text}")

    data = r.json() or {}
    if not data.get("status"):
        raise RuntimeError(f"Paystack verify returned status=false: {data}")

    return data
