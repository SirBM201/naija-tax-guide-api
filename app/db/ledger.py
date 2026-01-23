# app/db/ledger.py
from __future__ import annotations

import logging
from typing import Optional

from supabase import create_client

from app.core.config import SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
from app.core.utils import now_utc, iso


_sb = None


def _client():
    global _sb
    if _sb is not None:
        return _sb
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("Supabase ENV not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).")
    _sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    return _sb


def ledger_add(wa_phone: str, delta: int, reason: str) -> None:
    """
    Write a ledger entry. Non-fatal if table doesn't exist.
    """
    if not wa_phone:
        return

    sb = _client()
    payload = {
        "wa_phone": wa_phone,
        "delta": int(delta or 0),
        "reason": (reason or "").strip()[:80],
        "created_at": iso(now_utc()),
    }

    try:
        sb.table("usage_ledger").insert(payload).execute()
    except Exception as e:
        # Don't break the app if ledger table isn't ready
        logging.warning("ledger_add skipped (non-fatal): %s", e)
