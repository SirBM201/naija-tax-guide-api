import os
import uuid
import requests
from typing import Dict, Any, Optional

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()

# Amounts in kobo (₦)
PLAN_AMOUNTS_KOBO = {
    "monthly": 330000,     # ₦3,300
    "quarterly": 850000,   # ₦8,500
    "yearly": 3200000,     # ₦32,000
}

def paystack_init_transaction(
    *,
    email: str,
    amount_kobo: int,
    callback_url: str,
    metadata: Dict[str, Any],
    reference: Optional[str] = None,
) -> Dict[str, Any]:
    if not PAYSTACK_SECRET_KEY:
        raise RuntimeError("PAYSTACK_SECRET_KEY is not set")

    ref = reference or f"ntg_{uuid.uuid4().hex}"

    url = "https://api.paystack.co/transaction/initialize"
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "email": email,
        "amount": int(amount_kobo),
        "reference": ref,
        "callback_url": callback_url,
        "metadata": metadata,
    }

    r = requests.post(url, json=payload, headers=headers, timeout=30)
    data = r.json()

    if not data.get("status"):
        # Paystack uses status=false on error
        msg = data.get("message") or "Paystack initialize failed"
        raise RuntimeError(msg)

    return {
        "reference": ref,
        "authorization_url": data["data"]["authorization_url"],
        "access_code": data["data"]["access_code"],
    }
