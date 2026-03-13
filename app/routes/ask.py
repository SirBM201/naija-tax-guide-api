from __future__ import annotations

import os
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request

from app.services.ask_service import ask_guarded
from app.services.web_auth_service import get_account_id_from_request

bp = Blueprint("ask", __name__)


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _safe_json() -> Dict[str, Any]:
    return request.get_json(silent=True) or {}


def _extract_account_id(auth_result: Any) -> tuple[Optional[str], Dict[str, Any]]:
    """
    Normalizes whatever get_account_id_from_request returns into:
      (account_id, auth_debug)

    Supported shapes:
    - "uuid-string"
    - ("uuid-string", {...debug...})
    - {"ok": True, "account_id": "...", ...}
    - {"account_id": "..."}
    """
    if isinstance(auth_result, str):
        account_id = auth_result.strip()
        return (account_id or None, {})

    if isinstance(auth_result, tuple):
        if len(auth_result) >= 1:
            first = auth_result[0]
            second = auth_result[1] if len(auth_result) > 1 and isinstance(auth_result[1], dict) else {}
            if isinstance(first, str):
                account_id = first.strip()
                return (account_id or None, second)
        return (None, {"error": "invalid_auth_tuple", "raw_type": str(type(auth_result))})

    if isinstance(auth_result, dict):
        account_id = str(auth_result.get("account_id") or "").strip()
        debug = dict(auth_result)
        return (account_id or None, debug)

    return (None, {"error": "unsupported_auth_result", "raw_type": str(type(auth_result))})


@bp.post("")
def ask():
    payload = _safe_json()
    question = str(payload.get("question") or "").strip()
    lang = str(payload.get("lang") or "en").strip() or "en"
    channel = str(payload.get("channel") or "web").strip() or "web"

    if not question:
        return jsonify(
            {
                "ok": False,
                "error": "missing_question",
                "message": "Question is required.",
            }
        ), 400

    auth_raw = get_account_id_from_request(request)
    account_id, auth_debug = _extract_account_id(auth_raw)

    if not account_id:
        body: Dict[str, Any] = {
            "ok": False,
            "error": "unauthorized",
            "message": "Authentication required.",
        }
        if _truthy(os.getenv("DEBUG_AI")) or _truthy(os.getenv("SHOW_ASK_DEBUG")):
            body["debug"] = {"auth": auth_debug}
        return jsonify(body), 401

    try:
        result = ask_guarded(
            account_id=account_id,
            question=question,
            lang=lang,
            channel=channel,
        )

        if not isinstance(result, dict):
            return jsonify(
                {
                    "ok": False,
                    "error": "invalid_ask_result",
                    "message": "Ask service returned an invalid response.",
                }
            ), 500

        result.setdefault("ok", True)
        return jsonify(result), 200

    except Exception as exc:
        body: Dict[str, Any] = {
            "ok": False,
            "error": "ask_failed",
            "message": "We could not complete your request right now.",
        }

        if _truthy(os.getenv("DEBUG_AI")) or _truthy(os.getenv("SHOW_ASK_DEBUG")):
            body["debug"] = {
                "exception_type": exc.__class__.__name__,
                "exception": str(exc),
                "auth": auth_debug,
                "account_id": account_id,
            }

        return jsonify(body), 500
