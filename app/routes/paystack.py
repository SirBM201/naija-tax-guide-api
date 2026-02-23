from __future__ import annotations

import os
from typing import Any, Dict, Tuple

from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase
from app.services.plans_service import get_plan
from app.services.paystack_service import (
    create_reference,
    initialize_transaction,
    verify_transaction,
    paystack_debug_snapshot,
)
from app.services.subscriptions_service import activate_subscription_now

paystack_bp = Blueprint("paystack", __name__)


def _sb():
    return supabase() if callable(supabase) else supabase


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


PAYSTACK_DEBUG = _truthy(_env("PAYSTACK_DEBUG", "0"))


def _clip(s: str, n: int = 220) -> str:
    s = (s or "")
    return s if len(s) <= n else s[:n] + "…"


def _read_json_body() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Always returns a dict, never throws.
    meta is SAFE diagnostics for root-cause exposer.
    """
    meta: Dict[str, Any] = {
        "content_type": (request.headers.get("Content-Type") or "").strip(),
        "content_length": request.content_length,
        "json_parsed": False,
        "keys": [],
        "raw_preview": "",
    }

    body = request.get_json(silent=True)
    if isinstance(body, dict):
        meta["json_parsed"] = True
        meta["keys"] = sorted(list(body.keys()))
        return body, meta

    raw = request.get_data(cache=False, as_text=True) or ""
    meta["raw_preview"] = _clip(raw, 200)
    return {}, meta


@paystack_bp.post("/paystack/init")
def paystack_init():
    """
    Supports TWO formats:

    A) Plan-based (your original design)
    {
      "account_id": "<uuid>",
      "plan_code": "monthly|quarterly|yearly",
      "email": "user@email.com"
    }

    B) Direct amount (your PowerShell tests)
    {
      "email": "user@email.com",
      "amount_kobo": 20000,     # OR "amount": 20000
      "currency": "NGN",
      "metadata": { "account_id": "...", "plan_code": "...", "channel": "web" }
    }
    """
    body, meta = _read_json_body()

    # Common
    email = (str(body.get("email") or "")).strip().lower()
    currency = (str(body.get("currency") or "NGN")).strip().upper() or "NGN"

    # Plan-based
    account_id = (str(body.get("account_id") or "")).strip()
    plan_code = (str(body.get("plan_code") or "")).strip().lower()

    # Direct amount-based
    amount_kobo = body.get("amount_kobo", None)
    if amount_kobo is None:
        amount_kobo = body.get("amount", None)  # allow "amount" as kobo
    metadata = body.get("metadata") if isinstance(body.get("metadata"), dict) else {}

    # Decide mode:
    use_plan_mode = bool(account_id and plan_code and email)

    if not email or "@" not in email:
        out = {"ok": False, "error": "invalid_email"}
        if PAYSTACK_DEBUG:
            out["debug"] = {"why": "missing_or_invalid_email", "req": meta}
        return jsonify(out), 400

    # If plan mode: compute amount_kobo from plan price (naira -> kobo).
    if use_plan_mode:
        plan = get_plan(plan_code)
        if not plan or not plan.get("active", True):
            out = {"ok": False, "error": "invalid_plan"}
            if PAYSTACK_DEBUG:
                out["debug"] = {"why": "plan_not_found_or_inactive", "plan_code": plan_code, "req": meta}
            return jsonify(out), 400

        amount_naira = int(plan.get("price") or 0)
        if amount_naira <= 0:
            out = {"ok": False, "error": "invalid_plan_price"}
            if PAYSTACK_DEBUG:
                out["debug"] = {"why": "plan_price_invalid", "plan": plan, "req": meta}
            return jsonify(out), 400

        computed_amount_kobo = amount_naira * 100
        reference = create_reference("NTG")
        combined_metadata = {"account_id": account_id, "plan_code": plan_code, "purpose": "subscription"}
        # merge any extra metadata passed in
        for k, v in (metadata or {}).items():
            if k not in combined_metadata:
                combined_metadata[k] = v

        ok, init_resp = initialize_transaction(
            email=email,
            amount_kobo=computed_amount_kobo,
            reference=reference,
            currency=currency,
            metadata=combined_metadata,
        )

    else:
        # Direct-amount mode: require amount_kobo present
        if amount_kobo is None:
            out = {"ok": False, "error": "missing_amount", "message": "Provide amount_kobo (or amount) in kobo."}
            if PAYSTACK_DEBUG:
                out["debug"] = {"why": "no_amount_kobo_or_amount", "req": meta}
            return jsonify(out), 400

        # If account_id / plan_code not in top-level, allow inside metadata for your webhook/verify flow.
        reference = (str(body.get("reference") or "")).strip() or create_reference("NTG")

        ok, init_resp = initialize_transaction(
            email=email,
            amount_kobo=int(amount_kobo),
            reference=reference,
            currency=currency,
            metadata=metadata or {},
            callback_url=str(body.get("callback_url") or "").strip() or None,
        )

    # Always store initiated transaction best-effort
    if ok:
        try:
            _sb().table("paystack_transactions").insert(
                {
                    "reference": init_resp.get("reference"),
                    "account_id": account_id or (metadata.get("account_id") if isinstance(metadata, dict) else None),
                    "plan_code": plan_code or (metadata.get("plan_code") if isinstance(metadata, dict) else None),
                    "amount": int((init_resp.get("amount_kobo") or 0) // 100),
                    "currency": init_resp.get("currency") or "NGN",
                    "status": "initiated",
                    "authorization_url": init_resp.get("authorization_url"),
                    "access_code": init_resp.get("access_code"),
                    "raw": init_resp.get("raw"),
                }
            ).execute()
        except Exception:
            pass

        return jsonify(
            {
                "ok": True,
                "authorization_url": init_resp.get("authorization_url"),
                "access_code": init_resp.get("access_code"),
                "reference": init_resp.get("reference"),
            }
        ), 200

    # Failed init -> always JSON
    if PAYSTACK_DEBUG and "debug" not in init_resp:
        init_resp["debug"] = {"req": meta}
    return jsonify(init_resp), 400


@paystack_bp.get("/paystack/verify/<reference>")
def paystack_verify(reference: str):
    """
    Verify a transaction and (if successful) activate the subscription.
    """
    reference = (reference or "").strip()
    if not reference:
        return jsonify({"ok": False, "error": "missing_reference"}), 400

    ok, data = verify_transaction(reference)
    if not ok:
        return jsonify(data), 400

    status = (data.get("status") or "").lower()
    metadata = data.get("metadata") or {}

    account_id = (str(metadata.get("account_id") or "")).strip()
    plan_code = (str(metadata.get("plan_code") or "")).strip().lower()

    # update transaction row (best-effort)
    try:
        _sb().table("paystack_transactions").update(
            {
                "paystack_status": status,
                "paid_at": data.get("paid_at"),
                "raw": data.get("raw") or data,
                "status": "success" if status == "success" else "failed",
            }
        ).eq("reference", reference).execute()
    except Exception:
        pass

    if status != "success":
        return jsonify({"ok": False, "error": "payment_not_successful", "paystack_status": status}), 400

    # If no plan_code/account_id, we still return success verify (payment OK),
    # but we cannot activate a subscription.
    if not account_id or not plan_code:
        return jsonify(
            {
                "ok": True,
                "reference": reference,
                "verified": True,
                "paystack_status": status,
                "subscription_activated": False,
                "warning": "missing_metadata_account_id_or_plan_code",
                "metadata": metadata,
            }
        ), 200

    sub = activate_subscription_now(account_id=account_id, plan_code=plan_code, status="active")

    return jsonify(
        {
            "ok": True,
            "reference": reference,
            "verified": True,
            "paystack_status": status,
            "subscription_activated": True,
            "subscription": sub,
        }
    ), 200


@paystack_bp.get("/_debug/paystack")
def debug_paystack():
    """
    SAFE debug endpoint (no secrets).
    Allowed if:
      - ADMIN_API_KEY (or ADMIN_KEY) is set and provided, OR
      - PAYSTACK_DEBUG=1 (temporary dev mode)
    """
    admin_key = _env("ADMIN_API_KEY", "") or _env("ADMIN_KEY", "")
    incoming = (request.headers.get("X-Admin-Key") or "").strip()

    if admin_key:
        if incoming != admin_key:
            return jsonify({"ok": False, "error": "forbidden", "why": "missing_or_invalid_admin_key"}), 403
        return jsonify({"ok": True, "paystack": paystack_debug_snapshot()}), 200

    if not PAYSTACK_DEBUG:
        return jsonify({"ok": False, "error": "forbidden", "why": "set_ADMIN_API_KEY_or_enable_PAYSTACK_DEBUG"}), 403

    return jsonify({"ok": True, "paystack": paystack_debug_snapshot()}), 200
