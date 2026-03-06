# app/routes/ask.py
from __future__ import annotations

import os
from flask import Blueprint, jsonify, request

from app.services.ask_service import ask_guarded
from app.services.web_auth_service import get_account_id_from_request
from app.services.subscription_guard import require_active_subscription

bp = Blueprint("ask", __name__)


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


def _debug_enabled() -> bool:
    return _truthy(_env("ASK_DEBUG", "0")) or _truthy(_env("DEBUG", "0"))


def _subscription_bypass_enabled() -> bool:
    """
    DEV ONLY.
    Keep OFF in production.
    """
    return _truthy(_env("DEV_BYPASS_SUBSCRIPTION", "0"))


def _get_bearer_token() -> str:
    h = (request.headers.get("Authorization") or "").strip()
    if h.lower().startswith("bearer "):
        return h[7:].strip()
    return ""


def _is_dev_bypass_request() -> bool:
    """
    Allow dev bypass ONLY when the request includes the correct token.
    """
    expected = (_env("BYPASS_TOKEN") or _env("DEV_BYPASS_TOKEN") or "").strip()
    if not expected:
        return False

    bearer = _get_bearer_token()
    x_token = (request.headers.get("X-Auth-Token") or "").strip()

    return bearer == expected or x_token == expected


@bp.post("/ask")
def ask():
    """
    Paid AI endpoint.
    Requires:
      - valid session / token
      - active subscription (unless explicit dev bypass is enabled)
    Body:
    {
      "question": "<text>",
      "lang": "en|pcm|yo|ig|ha" (optional),
      "channel": "<optional>"
    }
    """
    body = request.get_json(silent=True) or {}

    question = (body.get("question") or "").strip()
    if not question:
        return jsonify({"ok": False, "error": "question_required"}), 400

    # Explicit dev bypass token support
    if _is_dev_bypass_request():
        body["__bypass"] = True

    # Derive authenticated account from cookie / bearer
    account_id, auth_debug = get_account_id_from_request(request)
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized", "debug": auth_debug}), 401

    body["account_id"] = account_id
    body.setdefault("provider", "web")
    body.setdefault("__auth_source", auth_debug)

    # Subscription enforcement
    bypass_sub = _subscription_bypass_enabled() and bool(body.get("__bypass"))
    if not bypass_sub:
        sub = require_active_subscription(account_id)
        if not sub.get("ok"):
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": "subscription_required",
                        "root_cause": sub.get("root_cause"),
                        "fix": sub.get("fix"),
                        "details": sub.get("details"),
                        "debug": {
                            "auth": auth_debug,
                            "subscription_guard": sub,
                        },
                    }
                ),
                402,
            )

        body["__subscription"] = sub.get("subscription")
    else:
        body["__subscription_bypass"] = True

    try:
        resp = ask_guarded(body)

        status = 200
        if not resp.get("ok"):
            if resp.get("error") in {"question_required", "invalid_request", "account_required", "account_invalid"}:
                status = 400
            elif resp.get("error") in {"unauthorized", "missing_token", "invalid_token", "session_expired"}:
                status = 401
            elif resp.get("error") in {"subscription_required", "insufficient_credits"}:
                status = 402
            else:
                status = 500

        return jsonify(resp), status

    except Exception as e:
        if _debug_enabled():
            return jsonify(
                {
                    "ok": False,
                    "error": "ask_failed",
                    "root_cause": f"{type(e).__name__}: {str(e)}",
                    "fix": "Check ask_service, subscription_guard, and dependent backend services.",
                }
            ), 500

        return jsonify({"ok": False, "error": "ask_failed"}), 500
