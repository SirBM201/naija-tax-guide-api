# app/services/qa_cache_service.py

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ..core.supabase_client import supabase
from .response_refiner import refine_answer, looks_like_error_answer


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def find_cached_answer(normalized_question: str, lang: str, *, max_results: int = 1) -> Optional[Dict[str, Any]]:
    """
    Returns the best cache row OR None.
    Also self-heals: if the stored answer is an error string, it will be disabled best-effort.
    """
    if not normalized_question:
        return None

    l = (lang or "en").strip().lower() or "en"

    try:
        res = (
            supabase()
            .table("qa_cache")
            .select("id,answer,source,priority,lang,enabled")
            .eq("normalized_question", normalized_question)
            .eq("lang", l)
            .eq("enabled", True)
            .order("priority", desc=True)
            .order("last_used_at", desc=True)
            .limit(int(max_results))
            .execute()
        )
        if not res.data:
            return None

        row = res.data[0]
        ans = (row.get("answer") or "").strip()
        if not ans:
            return None

        # If this row contains an error-like string, disable it so it stops poisoning cache.
        if looks_like_error_answer(ans):
            try:
                supabase().table("qa_cache").update({"enabled": False}).eq("id", row["id"]).execute()
            except Exception:
                pass
            return None

        # Refine the cached answer before returning (shared behavior across channels)
        refined = refine_answer(ans, lang=l, source=str(row.get("source") or "cache"))
        if not refined:
            # disable if refinement rejects it
            try:
                supabase().table("qa_cache").update({"enabled": False}).eq("id", row["id"]).execute()
            except Exception:
                pass
            return None

        row["answer"] = refined
        return row

    except Exception:
        return None


def touch_cache_best_effort(row_id: str) -> None:
    if not row_id:
        return

    try:
        supabase().rpc("touch_qa_cache", {"p_id": row_id}).execute()
        return
    except Exception:
        pass

    try:
        got = supabase().table("qa_cache").select("use_count").eq("id", row_id).limit(1).execute()
        cur = 0
        if got.data:
            cur = int(got.data[0].get("use_count") or 0)
        supabase().table("qa_cache").update(
            {"use_count": cur + 1, "last_used_at": _now_utc_iso()}
        ).eq("id", row_id).execute()
    except Exception:
        pass


def upsert_ai_answer_to_cache_best_effort(normalized_question: str, answer: str, lang: str) -> None:
    """
    Only saves *valid refined* answers.
    NEVER saves error strings.
    """
    nq = (normalized_question or "").strip()
    l = (lang or "en").strip().lower() or "en"
    if not nq:
        return

    refined = refine_answer(answer, lang=l, source="ai")
    if not refined:
        return

    now_iso = _now_utc_iso()
    db = supabase()

    try:
        existing = (
            db.table("qa_cache")
            .select("id")
            .eq("normalized_question", nq)
            .eq("lang", l)
            .limit(1)
            .execute()
        )

        if existing.data:
            row_id = existing.data[0]["id"]
            db.table("qa_cache").update(
                {
                    "answer": refined,
                    "source": "ai",
                    "enabled": True,
                    "last_used_at": now_iso,
                }
            ).eq("id", row_id).execute()
            return

        db.table("qa_cache").insert(
            {
                "normalized_question": nq,
                "answer": refined,
                "tags": [],
                "use_count": 0,
                "last_used_at": now_iso,
                "created_at": now_iso,
                "source": "ai",
                "enabled": True,
                "priority": 0,
                "lang": l,
            }
        ).execute()

    except Exception:
        pass
