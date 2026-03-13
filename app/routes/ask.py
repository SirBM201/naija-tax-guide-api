from __future__ import annotations

import os
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, jsonify, request

from app.services.ask_service import ask_guarded
from app.services.web_auth_service import get_account_id_from_request

bp = Blueprint("ask", __name__)


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _debug_enabled() -> bool:
    return _truthy(os.getenv("DEBUG_AI")) or _truthy(os.getenv("SHOW_ASK_DEBUG"))


def _safe_json() -> Dict[str, Any]:
    return request.get_json(silent=True) or {}


def _extract_account_id(auth_result: Any) -> Tuple[Optional[str], Dict[str, Any]]:
    """
    Normalize whatever get_account_id_from_request returns into:
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
        first = auth_result[0] if len(auth_result) > 0 else None
        second = auth_result[1] if len(auth_result) > 1 and isinstance(auth_result[1], dict) else {}

        if isinstance(first, str):
            account_id = first.strip()
            return (account_id or None, second)

        return (None, {"error": "invalid_auth_tuple", "raw": repr(auth_result)})

    if isinstance(auth_result, dict):
        account_id = str(auth_result.get("account_id") or "").strip()
        return (account_id or None, dict(auth_result))

    return (None, {"error": "unsupported_auth_result", "raw_type": str(type(auth_result))})


def _build_unauthorized(auth_debug: Dict[str, Any]):
    body: Dict[str, Any] = {
        "ok": False,
        "error": "unauthorized",
        "message": "Authentication required.",
    }
    if _debug_enabled():
        body["debug"] = {"auth": auth_debug}
    return jsonify(body), 401


def _handle_ask():
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
        return _build_unauthorized(auth_debug)

    try:
        result = ask_guarded(
            account_id=account_id,
            question=question,
            lang=lang,
            channel=channel,
        )

        if not isinstance(result, dict):
            body: Dict[str, Any] = {
                "ok": False,
                "error": "invalid_ask_result",
                "message": "Ask service returned an invalid response.",
            }
            if _debug_enabled():
                body["debug"] = {
                    "result_type": str(type(result)),
                    "account_id": account_id,
                }
            return jsonify(body), 500

        result.setdefault("ok", True)
        return jsonify(result), 200

    except Exception as exc:
        body: Dict[str, Any] = {
            "ok": False,
            "error": "ask_failed",
            "message": "We could not complete your request right now.",
        }

        if _debug_enabled():
            body["debug"] = {
                "exception_type": exc.__class__.__name__,
                "exception": str(exc),
                "account_id": account_id,
                "auth": auth_debug,
            }

        return jsonify(body), 500


@bp.route("", methods=["POST", "OPTIONS"], strict_slashes=False)
def ask_root_no_slash():
    if request.method == "OPTIONS":
        return ("", 200)
    return _handle_ask()


@bp.route("/", methods=["POST", "OPTIONS"], strict_slashes=False)
def ask_root_with_slash():
    if request.method == "OPTIONS":
        return ("", 200)
    return _handle_ask()
