from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.core.supabase_client import supabase
from app.services.ai_service import create_embedding


def _sb():
    return supabase() if callable(supabase) else supabase


def _clip(v: Any, n: int = 260) -> str:
    s = str(v or "")
    return s if len(s) <= n else s[:n] + "..."


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return default


def semantic_match_question(
    *,
    question: str,
    lang: str = "en",
    jurisdiction: str = "nigeria",
    match_count: int = 5,
    min_trust: float = 0.75,
) -> Dict[str, Any]:
    question = (question or "").strip()
    lang = (lang or "en").strip() or "en"
    jurisdiction = (jurisdiction or "nigeria").strip().lower() or "nigeria"

    if not question:
        return {
            "ok": False,
            "error": "question_required",
            "root_cause": "missing_question",
            "fix": "Provide a non-empty question for semantic matching.",
        }

    emb = create_embedding(question)
    if not emb.get("ok"):
        return emb

    vector = emb.get("embedding")
    if not vector:
        return {
            "ok": False,
            "error": "embedding_missing",
            "root_cause": "Embedding provider returned no vector.",
            "fix": "Check embedding provider configuration.",
        }

    try:
        res = _sb().rpc(
            "match_qa_embeddings",
            {
                "query_embedding": vector,
                "match_count": int(match_count),
                "match_lang": lang,
                "match_jurisdiction": jurisdiction,
                "min_trust": float(min_trust),
            },
        ).execute()

        rows = getattr(res, "data", None) or []
        return {
            "ok": True,
            "matches": rows,
            "count": len(rows),
            "embedding_meta": {
                "provider": emb.get("provider"),
                "model": emb.get("model"),
                "dimensions": emb.get("dimensions"),
            },
        }

    except Exception as e:
        return {
            "ok": False,
            "error": "semantic_match_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
            "fix": "Check pgvector setup, SQL function, and RPC access.",
        }


def choose_best_semantic_match(
    matches: List[Dict[str, Any]],
    *,
    direct_threshold: float = 0.92,
    review_threshold: float = 0.85,
) -> Dict[str, Any]:
    if not matches:
        return {
            "ok": True,
            "decision": "miss",
            "best_match": None,
            "reason": "no_matches",
        }

    best = matches[0]
    similarity = _safe_float(best.get("similarity"), 0.0)
    trust_score = _safe_float(best.get("trust_score"), 0.0)
    hit_count = float(int(best.get("hit_count") or 0))

    adjusted_score = (similarity * 0.80) + (trust_score * 0.18) + (min(hit_count, 20) * 0.001)

    if adjusted_score >= direct_threshold:
        return {
            "ok": True,
            "decision": "direct_hit",
            "best_match": best,
            "score": adjusted_score,
        }

    if adjusted_score >= review_threshold:
        return {
            "ok": True,
            "decision": "review_hit",
            "best_match": best,
            "score": adjusted_score,
        }

    return {
        "ok": True,
        "decision": "miss",
        "best_match": best,
        "score": adjusted_score,
    }


def increment_embedding_hit_best_effort(embedding_id: str) -> None:
    embedding_id = (embedding_id or "").strip()
    if not embedding_id:
        return

    try:
        current = (
            _sb()
            .table("qa_embeddings")
            .select("hit_count")
            .eq("id", embedding_id)
            .limit(1)
            .execute()
        )
        rows = getattr(current, "data", None) or []
        count = int((rows[0].get("hit_count") if rows else 0) or 0)

        _sb().table("qa_embeddings").update(
            {
                "hit_count": count + 1,
            }
        ).eq("id", embedding_id).execute()
    except Exception:
        return


def insert_semantic_embedding_best_effort(
    *,
    cache_id: str,
    question: str,
    normalized_question: Optional[str] = None,
    canonical_key: Optional[str] = None,
    lang: str = "en",
    jurisdiction: str = "nigeria",
    tax_type: Optional[str] = None,
    audience: Optional[str] = None,
    trust_score: float = 0.85,
    review_status: str = "approved",
    policy_version: Optional[str] = None,
    source_type: str = "cache",
) -> Dict[str, Any]:
    cache_id = (cache_id or "").strip()
    question = (question or "").strip()
    normalized_question = (normalized_question or "").strip() or None
    canonical_key = (canonical_key or "").strip() or None
    lang = (lang or "en").strip() or "en"
    jurisdiction = (jurisdiction or "nigeria").strip().lower() or "nigeria"
    review_status = (review_status or "approved").strip().lower() or "approved"
    source_type = (source_type or "cache").strip().lower() or "cache"

    if not cache_id:
        return {
            "ok": False,
            "error": "cache_id_required",
            "root_cause": "missing_cache_id",
        }

    if not question:
        return {
            "ok": False,
            "error": "question_required",
            "root_cause": "missing_question",
        }

    emb = create_embedding(normalized_question or question)
    if not emb.get("ok"):
        return emb

    vector = emb.get("embedding")
    if not vector:
        return {
            "ok": False,
            "error": "embedding_missing",
            "root_cause": "Embedding provider returned no vector.",
        }

    payload = {
        "cache_id": cache_id,
        "question": question,
        "normalized_question": normalized_question,
        "canonical_key": canonical_key,
        "lang": lang,
        "jurisdiction": jurisdiction,
        "tax_type": tax_type,
        "audience": audience,
        "trust_score": float(trust_score),
        "review_status": review_status,
        "policy_version": policy_version,
        "source_type": source_type,
        "embedding": vector,
    }

    try:
        _sb().table("qa_embeddings").insert(payload).execute()
        return {
            "ok": True,
            "cache_id": cache_id,
            "provider": emb.get("provider"),
            "model": emb.get("model"),
        }
    except Exception as e:
        return {
            "ok": False,
            "error": "semantic_embedding_insert_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
            "fix": "Check qa_embeddings schema, vector extension, and backend DB access.",
        }
