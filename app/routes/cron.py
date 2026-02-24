# app/routes/cron.py
from __future__ import annotations

import traceback
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request

from app.core.security import require_admin_key
from app.core.supabase_client import supabase

bp = Blueprint("cron", __name__)

DEFAULT_BATCH = 1000
MAX_BATCH = 5000


def _debug_enabled() -> bool:
    return (request.headers.get("X-Debug") or "").strip() == "1"


def _rid() -> str:
    # set by app/__init__.py before_request
    return str(request.environ.get("REQUEST_ID") or "")


def _get_json() -> Dict[str, Any]:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _get_batch_limit(payload: Dict[str, Any]) -> int:
    v = payload.get("batch_limit", DEFAULT_BATCH)
    try:
        n = int(v)
    except Exception:
        n = DEFAULT_BATCH
    n = max(1, min(MAX_BATCH, n))
    return n


def _err(e: Exception, *, where: str, extra: Optional[Dict[str, Any]] = None):
    out: Dict[str, Any] = {
        "ok": False,
        "request_id": _rid(),
        "error": type(e).__name__,
        "message": str(e)[:800],
        "where": where,
    }
    if extra:
        out["extra"] = extra
    if _debug_enabled():
        out["traceback"] = traceback.format_exc(limit=80)
        out["debug"] = {
            "path": request.path,
            "method": request.method,
            "content_type": request.content_type,
            "headers": {
                "X-Admin-Key": "present" if (request.headers.get("X-Admin-Key") or "") else "missing",
                "X-Debug": request.headers.get("X-Debug"),
            },
        }
    return jsonify(out), 500


@bp.get("/internal/cron/ping")
def cron_ping():
    try:
        guard = require_admin_key()
        if guard is not None:
            return guard
        return jsonify({"ok": True, "request_id": _rid(), "pong": True}), 200
    except Exception as e:
        return _err(e, where="cron.ping")


@bp.get("/internal/cron/selftest")
def cron_selftest():
    """
    Helps you instantly see if:
    - admin key guard passes
    - request_id exists
    - request headers are present
    """
    try:
        guard = require_admin_key()
        if guard is not None:
            return guard
        return jsonify(
            {
                "ok": True,
                "request_id": _rid(),
                "path": request.path,
                "method": request.method,
                "admin_key_header_present": bool((request.headers.get("X-Admin-Key") or "").strip()),
                "debug_header": (request.headers.get("X-Debug") or "").strip(),
            }
        ), 200
    except Exception as e:
        return _err(e, where="cron.selftest")


@bp.post("/internal/cron/expire-subscriptions")
def expire_subscriptions():
    guard = require_admin_key()
    if guard is not None:
        return guard

    payload = _get_json()
    batch_limit = _get_batch_limit(payload)

    try:
        res = supabase().rpc("expire_overdue_subscriptions", {"batch_limit": batch_limit}).execute()
        data = getattr(res, "data", None)

        if isinstance(data, list):
            data = data[0] if data else {}

        return jsonify(
            {
                "ok": True,
                "request_id": _rid(),
                "method": "rpc",
                "rpc": "expire_overdue_subscriptions",
                "batch_limit": batch_limit,
                "result": data,
            }
        ), 200
    except Exception as e:
        return _err(e, where="cron.expire_subscriptions(rpc)", extra={"batch_limit": batch_limit})


@bp.post("/internal/cron/expire-credits")
def expire_credits():
    guard = require_admin_key()
    if guard is not None:
        return guard

    payload = _get_json()
    batch_limit = _get_batch_limit(payload)

    try:
        res = supabase().rpc("expire_ai_credits", {"batch_limit": batch_limit}).execute()
        data = getattr(res, "data", None)

        if isinstance(data, list):
            data = data[0] if data else {}

        return jsonify(
            {
                "ok": True,
                "request_id": _rid(),
                "method": "rpc",
                "rpc": "expire_ai_credits",
                "batch_limit": batch_limit,
                "result": data,
            }
        ), 200
    except Exception as e:
        return _err(e, where="cron.expire_credits(rpc)", extra={"batch_limit": batch_limit})
