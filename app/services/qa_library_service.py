# app/services/qa_library_service.py
from __future__ import annotations

from typing import Any, Dict, Optional
from datetime import datetime, timezone

from ..core.supabase_client import supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def find_library_answer(normalized_question: str, lang: str) -> Optional[Dict[str, Any]]:
    """
    Returns the best matching curated answer from qa_library (if present).
    We try robustly because schemas differ across setups.

    Expected (common) columns:
      - id
      - normalized_question (text)
      - question (text)
      - answer (text)   OR response/solution
      - enabled (bool)  [optional]
      - lang (text)     [optional]
      - priority (int)  [optional]
      - last_used_at    [optional]
    """
    nq = (normalized_question or "").strip()
    l = (lang or "en").strip().lower()
    if not nq:
        return None

    db = supabase()

    # Attempt 1: strict match by normalized_question (+ lang if it exists)
    # We catch schema errors and fall back.
    try:
        q = (
            db.table("qa_library")
            .select("id,answer,lang,enabled,priority,last_used_at")
            .eq("normalized_question", nq)
        )
        # if lang column exists in your table, this will work; if not, it will throw and we fall back
        q = q.eq("lang", l)
        q = q.eq("enabled", True)
        q = q.order("priority", desc=True).order("last_used_at", desc=True).limit(1)
        res = q.execute()
        if res.data:
            row = res.data[0]
            ans = (row.get("answer") or "").strip()
            if ans:
                return {"id": row.get("id"), "answer": ans}
    except Exception:
        pass

    # Attempt 2: strict match by normalized_question (no lang/enabled)
    try:
        res = (
            db.table("qa_library")
            .select("id,answer,priority,last_used_at")
            .eq("normalized_question", nq)
            .order("priority", desc=True)
            .order("last_used_at", desc=True)
            .limit(1)
            .execute()
        )
        if res.data:
            row = res.data[0]
            ans = (row.get("answer") or "").strip()
            if ans:
                return {"id": row.get("id"), "answer": ans}
    except Exception:
        pass

    # Attempt 3: some schemas use "response" or "solution" instead of "answer"
    for alt_col in ("response", "solution"):
        try:
            res = (
                db.table("qa_library")
                .select(f"id,{alt_col},priority,last_used_at")
                .eq("normalized_question", nq)
                .order("priority", desc=True)
                .order("last_used_at", desc=True)
                .limit(1)
                .execute()
            )
            if res.data:
                row = res.data[0]
                ans = (row.get(alt_col) or "").strip()
                if ans:
                    return {"id": row.get("id"), "answer": ans}
        except Exception:
            pass

    return None


def touch_library_best_effort(row_id: str) -> None:
    """
    Optional usage tracking. If your qa_library doesn't have these columns,
    this will just fail silently (best-effort).
    """
    rid = (row_id or "").strip()
    if not rid:
        return

    db = supabase()
    now_iso = _now_utc().isoformat()

    # Try an atomic RPC if you create one later
    try:
        db.rpc("touch_qa_library", {"p_id": rid}).execute()
        return
    except Exception:
        pass

    # Best-effort update if columns exist
    try:
        got = db.table("qa_library").select("use_count").eq("id", rid).limit(1).execute()
        cur = 0
        if got.data:
            cur = int(got.data[0].get("use_count") or 0)

        db.table("qa_library").update(
            {"use_count": cur + 1, "last_used_at": now_iso}
        ).eq("id", rid).execute()
    except Exception:
        pass
