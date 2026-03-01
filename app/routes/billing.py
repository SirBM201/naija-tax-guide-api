# app/routes/billing.py
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase
from app.services.plans_service import get_plan, list_plans
from app.services.web_auth_service import get_account_id_from_request
from app.services.paystack_service import (
    create_reference,
    initialize_transaction,
    verify_transaction,
    verify_webhook_signature,
)

bp = Blueprint("billing", __name__)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _sb():
    return supabase() if callable(supabase) else supabase


def _safe_execute(fn, *args, **kwargs):
    """
    Supabase tables may not exist yet or schema might differ.
    We never want billing endpoints to crash the whole API.
    """
    try:
        return fn(*args, **kwargs), None
    except Exception as e:
        return None, repr(e)


def _get_or_create_web_account(email: str) -> Dict[str, Any]:
    """
    Create/lookup account for Paystack billing without OTP.
    Uses:
      accounts.provider='web'
      accounts.provider_user_id=email

    Returns the accounts row.
    """
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("missing_email")

    q = (
        _sb()
        .table("accounts")
        .select("id,account_id,provider,provider_user_id,created_at")
        .eq("provider", "web")
        .eq("provider_user_id", email)
        .limit(1)
        .execute()
    )
    rows = getattr(q, "data", None) or []
    if rows:
        return rows[0]

    ins = _sb().table("accounts").insert({"provider": "web", "provider_user_id": email}).execute()
    rows2 = getattr(ins, "data", None) or []
    if not rows2:
        raise RuntimeError("account_create_failed")
    return rows2[0]


def _insert_payment_row(*, reference: str, account_id: str, plan_code: str, amount_ngn: int, raw: Optional[dict] = None):
    now = _now_utc().isoformat()
    row = {
        "provider": "paystack",
        "reference": reference,
        "account_id": account_id,
        "plan_code": plan_code,
        "amount": int(amount_ngn),
        "currency": "NGN",
        "status": "pending",
        "created_at": now,
        "updated_at": now,
        "raw": raw or None,
    }
    _sb().table("payments").insert(row).execute()


def _mark_payment(*, reference: str, status: str, raw: Optional[dict] = None):
    now = _now_utc().isoformat()
    patch: Dict[str, Any] = {"status": status, "updated_at": now}
    if status == "success":
        patch["paid_at"] = now
    if raw is not None:
        patch["raw"] = raw
    _sb().table("payments").update(patch).eq("reference", reference).execute()


def _upsert_subscription(*, account_id: str, plan_code: str, duration_days: int) -> Dict[str, Any]:
    """
    Simple approach:
      - If account has a subscription row -> update it
      - else insert
    """
    now = _now_utc()
    expires_at = now + timedelta(days=int(duration_days))

    # find existing (latest)
    q = (
        _sb()
        .table("user_subscriptions")
        .select("id,account_id,plan_code,active,expires_at")
        .eq("account_id", account_id)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    rows = getattr(q, "data", None) or []

    if rows:
        sub_id = rows[0]["id"]
        upd = (
            _sb()
            .table("user_subscriptions")
            .update(
                {
                    "plan_code": plan_code,
                    "active": True,
                    "started_at": now.isoformat(),
                    "expires_at": expires_at.isoformat(),
                    "updated_at": now.isoformat(),
                }
            )
            .eq("id", sub_id)
            .execute()
        )
        out = getattr(upd, "data", None) or []
        return out[0] if out else {
            "id": sub_id,
            "account_id": account_id,
            "plan_code": plan_code,
            "active": True,
            "expires_at": expires_at.isoformat(),
        }

    ins = (
        _sb()
        .table("user_subscriptions")
        .insert(
            {
                "account_id": account_id,
                "plan_code": plan_code,
                "active": True,
                "started_at": now.isoformat(),
                "expires_at": expires_at.isoformat(),
                "created_at": now.isoformat(),
                "updated_at": now.isoformat(),
            }
        )
        .execute()
    )
    out = getattr(ins, "data", None) or []
    return out[0] if out else {
        "account_id": account_id,
        "plan_code": plan_code,
        "active": True,
        "expires_at": expires_at.isoformat(),
    }


@bp.get("/billing/plans")
def billing_plans():
    active_only = (request.args.get("active_only") or "1").strip() != "0"
    plans = list_plans(active_only=active_only)
    return jsonify({"ok": True, "plans": plans}), 200


@bp.get("/billing/plans/<plan_code>")
def billing_plan(plan_code: str):
    p = get_plan(plan_code)
    if not p:
        return jsonify({"ok": False, "error": "plan_not_found"}), 404
    return jsonify({"ok": True, "plan": p}), 200


@bp.get("/billing/me")
def billing_me():
    """
    Minimal auth probe endpoint for the frontend.
    Uses SAME cookie/bearer validation as /web/auth/me.
    """
    account_id, debug = get_account_id_from_request(request)
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401

    return jsonify({"ok": True, "account_id": account_id, "debug": debug}), 200


@bp.post("/billing/checkout")
def billing_checkout():
    """
    Start Paystack payment WITHOUT relying on OTP/auth.
    Body:
      { "plan_code": "monthly|quarterly|yearly", "email": "user@email.com" }
    """
    body = request.get_json(silent=True) or {}
    plan_code = (body.get("plan_code") or "").strip().lower()
    email = (body.get("email") or "").strip().lower()

    plan = get_plan(plan_code)
    if not plan or not plan.get("active", True):
        return jsonify({"ok": False, "error": "plan_not_found"}), 404

    try:
        acct = _get_or_create_web_account(email)
    except Exception as e:
        return jsonify({"ok": False, "error": "account_resolve_failed", "root_cause": repr(e)}), 400

    accounts_id = str(acct.get("id") or "")
    if not accounts_id:
        return jsonify({"ok": False, "error": "account_missing_id", "account": acct}), 400

    reference = create_reference("NTG")

    metadata = {
        "product": "naija_tax_guide",
        "plan_code": plan_code,
        "account_id": accounts_id,   # IMPORTANT: accounts.id (FK source of truth)
        "email": email,
    }

    # your paystack_service expects amount in KOBO already
    amount_kobo = int(plan["price"]) * 100

    try:
        ps = initialize_transaction(
            email=email,
            amount_kobo=amount_kobo,
            reference=reference,
            metadata=metadata,
        )
    except Exception as e:
        return jsonify({"ok": False, "error": "paystack_init_failed", "root_cause": repr(e)}), 400

    data = (ps or {}).get("data") or {}
    auth_url = data.get("authorization_url")

    # store payment row (best effort)
    _, pay_err = _safe_execute(
        _insert_payment_row,
        reference=reference,
        account_id=accounts_id,
        plan_code=plan_code,
        amount_ngn=int(plan["price"]),
        raw=ps,
    )

    return jsonify(
        {
            "ok": True,
            "authorization_url": auth_url,
            "reference": reference,
            "plan": plan,
            "account": {"id": accounts_id},
            "db_warning": pay_err,  # null if insert succeeded
        }
    ), 200


@bp.get("/billing/verify")
def billing_verify():
    """
    Verify transaction after redirect:
      GET /billing/verify?reference=NTG-xxxx
    Activates subscription on success.
    """
    reference = (request.args.get("reference") or "").strip()
    if not reference:
        return jsonify({"ok": False, "error": "missing_reference"}), 400

    try:
        ps = verify_transaction(reference)
    except Exception as e:
        return jsonify({"ok": False, "error": "paystack_verify_failed", "root_cause": repr(e)}), 400

    tx = (ps or {}).get("data") or {}
    status = (tx.get("status") or "").strip().lower()
    metadata = tx.get("metadata") or {}

    plan_code = (metadata.get("plan_code") or "").strip().lower()
    account_id = (metadata.get("account_id") or "").strip()

    if status != "success":
        _safe_execute(_mark_payment, reference=reference, status="failed", raw=ps)
        return jsonify({"ok": True, "paid": False, "status": status, "reference": reference, "data": tx}), 200

    if not plan_code or not account_id:
        return jsonify({"ok": False, "error": "missing_metadata", "metadata": metadata, "reference": reference}), 400

    plan = get_plan(plan_code)
    if not plan:
        return jsonify({"ok": False, "error": "plan_not_found", "plan_code": plan_code}), 404

    _safe_execute(_mark_payment, reference=reference, status="success", raw=ps)

    sub, sub_err = _safe_execute(
        _upsert_subscription,
        account_id=account_id,
        plan_code=plan_code,
        duration_days=int(plan["duration_days"]),
    )

    return jsonify(
        {
            "ok": True,
            "paid": True,
            "reference": reference,
            "plan": plan,
            "account_id": account_id,
            "subscription": sub,
            "db_warning": sub_err,
        }
    ), 200


@bp.post("/billing/webhook")
def billing_webhook():
    """
    Paystack webhook.
    - verifies signature using x-paystack-signature
    - stores idempotent event if table exists
    - activates subscription on charge.success
    """
    raw = request.get_data(cache=False) or b""
    sig = (request.headers.get("x-paystack-signature") or "").strip()

    if not verify_webhook_signature(raw, sig):
        return jsonify({"ok": False, "error": "invalid_signature"}), 401

    try:
        payload = json_payload = request.get_json(silent=True) or {}
    except Exception:
        payload = {}

    event = (payload.get("event") or "").strip().lower()
    data = payload.get("data") or {}
    reference = (data.get("reference") or "").strip()
    tx_id = str(data.get("id") or "")

    # best effort: store event idempotently
    if tx_id:
        def _insert_event():
            _sb().table("paystack_events").insert(
                {
                    "event_id": tx_id,
                    "event_type": event or "unknown",
                    "reference": reference or None,
                    "payload": payload,
                }
            ).execute()

        _safe_execute(_insert_event)

    if event == "charge.success":
        metadata = (data.get("metadata") or {})
        plan_code = (metadata.get("plan_code") or "").strip().lower()
        account_id = (metadata.get("account_id") or "").strip()

        if plan_code and account_id:
            plan = get_plan(plan_code)
            if plan:
                _safe_execute(_mark_payment, reference=reference, status="success", raw=payload)
                _safe_execute(
                    _upsert_subscription,
                    account_id=account_id,
                    plan_code=plan_code,
                    duration_days=int(plan["duration_days"]),
                )

    return jsonify({"ok": True}), 200
