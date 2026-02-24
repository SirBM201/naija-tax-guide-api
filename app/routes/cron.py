# app/routes/cron.py
from __future__ import annotations

import traceback
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request

from app.core.security import require_admin_key
from app.core.supabase_client import supabase

# If you still want to keep the Python service path as fallback:
# from app.services.subscriptions_service import expire_overdue_subscriptions

bp = Blueprint("cron", __name__)

DEFAULT_BATCH = 1000
MAX_BATCH = 5000


def _debug_enabled() -> bool:
    return (request.headers.get("X-Debug") or "").strip() == "1"


def _get_json() -> Dict[str, Any]:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _get_batch_limit(payload: Dict[str, Any]) -> int:
    v = payload.get("batch_limit", DEFAULT_BATCH)
    try:
        n = int(v)
    except Exception:
        n = DEFAULT_BATCH
    if n < 1:
        n = 1
    if n > MAX_BATCH:
        n = MAX_BATCH
    return n


def _err(e: Exception, *, where: str, extra: Optional[Dict[str, Any]] = None):
    out: Dict[str, Any] = {
        "ok": False,
        "error": type(e).__name__,
        "message": str(e)[:800],
        "where": where,
    }
    if extra:
        out["extra"] = extra
    if _debug_enabled():
        out["traceback"] = traceback.format_exc(limit=50)
        out["debug"] = {
            "path": request.path,
            "method": request.method,
            "content_type": request.content_type,
        }
    return jsonify(out), 500


@bp.post("/internal/cron/expire-subscriptions")
def expire_subscriptions():
    guard = require_admin_key()
    if guard is not None:
        return guard

    payload = _get_json()
    batch_limit = _get_batch_limit(payload)

    try:
        # Prefer DB RPC (fast + reliable + avoids Python/service drift)
        res = supabase().rpc("expire_overdue_subscriptions", {"batch_limit": batch_limit}).execute()
        data = getattr(res, "data", None)

        # Some supabase clients return list for single-row jsonb
        if isinstance(data, list):
            data = data[0] if data else {}

        return jsonify(
            {
                "ok": True,
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
                "method": "rpc",
                "rpc": "expire_ai_credits",
                "batch_limit": batch_limit,
                "result": data,
            }
        ), 200

    except Exception as e:
        return _err(e, where="cron.expire_credits(rpc)", extra={"batch_limit": batch_limit})


# Optional: quick sanity route (helps confirm auth + bp registration)
@bp.get("/internal/cron/ping")
def cron_ping():
    guard = require_admin_key()
    if guard is not None:
        return guard
    return jsonify({"ok": True, "pong": True}), 200
