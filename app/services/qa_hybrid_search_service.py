from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.core.supabase_client import supabase
from app.services.qa_cache_service import normalize_question_for_cache, derive_canonical_key
from app.services.qa_semantic_cache_service import semantic_match_question


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


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def exact_cache_match(
    *,
    question: str,
    lang: str = "en",
) -> Dict[str, Any]:
    question = (question or "").strip()
    lang = (lang or "en").strip() or "en"

    if not question:
        return {
            "ok": False,
            "error": "question_required",
            "root_cause": "missing_question",
        }

    normalized = normalize_question_for_cache(question)
    canonical_key = derive_canonical_key(question, lang=lang)

    try:
        res = _sb().rpc(
            "match_qa_cache_exact",
            {
                "search_normalized_question": normalized,
                "search_canonical_key": canonical_key,
                "match_lang": lang,
            },
        ).execute()

        rows = getattr(res, "data", None) or []
        row = rows[0] if rows else None

        return {
            "ok": True,
            "match": row,
            "normalized_question": normalized,
            "canonical_key": canonical_key,
        }
    except Exception as e:
        return {
            "ok": False,
            "error": "exact_cache_match_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
        }


def keyword_cache_match(
    *,
    question: str,
    lang: str = "en",
    limit: int = 5,
) -> Dict[str, Any]:
    question = (question or "").strip()
    lang = (lang or "en").strip() or "en"

    if not question:
        return {
            "ok": False,
            "error": "question_required",
            "root_cause": "missing_question",
        }

    normalized = normalize_question_for_cache(question)

    try:
        res = _sb().rpc(
            "match_qa_cache_keyword",
            {
                "search_text": normalized,
                "match_lang": lang,
                "match_limit": int(limit),
            },
        ).execute()

        rows = getattr(res, "data", None) or []
        return {
            "ok": True,
            "matches": rows,
            "normalized_question": normalized,
        }
    except Exception as e:
        return {
            "ok": False,
            "error": "keyword_cache_match_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
        }


def rank_hybrid_results(
    *,
    exact_match: Optional[Dict[str, Any]],
    keyword_matches: List[Dict[str, Any]],
    semantic_matches: List[Dict[str, Any]],
) -> Dict[str, Any]:
    candidates: List[Dict[str, Any]] = []

    if exact_match:
        candidates.append(
            {
                "mode": "exact",
                "row": exact_match,
                "score": 1.0000,
            }
        )

    for row in keyword_matches or []:
        keyword_score = _safe_float(row.get("keyword_score"), 0.0)
        priority = _safe_int(row.get("priority"), 0)
        use_count = _safe_int(row.get("use_count"), 0)

        score = min(
            0.90,
            0.55 + (keyword_score * 0.20) + (min(priority, 10) * 0.01) + (min(use_count, 20) * 0.005),
        )

        candidates.append(
            {
                "mode": "keyword",
                "row": row,
                "score": score,
            }
        )

    for row in semantic_matches or []:
        similarity = _safe_float(row.get("similarity"), 0.0)
        trust_score = _safe_float(row.get("trust_score"), 0.0)
        hit_count = _safe_int(row.get("hit_count"), 0)

        score = (similarity * 0.80) + (trust_score * 0.15) + (min(hit_count, 20) * 0.0025)

        candidates.append(
            {
                "mode": "semantic",
                "row": row,
                "score": score,
            }
        )

    if not candidates:
        return {
            "ok": True,
            "decision": "miss",
            "best": None,
            "candidates": [],
        }

    candidates.sort(key=lambda x: x["score"], reverse=True)
    best = candidates[0]

    score = _safe_float(best.get("score"), 0.0)

    if best["mode"] == "exact":
        decision = "direct_hit"
    elif score >= 0.92:
        decision = "direct_hit"
    elif score >= 0.85:
        decision = "review_hit"
    else:
        decision = "miss"

    return {
        "ok": True,
        "decision": decision,
        "best": best,
        "candidates": candidates[:10],
    }


def hybrid_match_question(
    *,
    question: str,
    lang: str = "en",
    jurisdiction: str = "nigeria",
) -> Dict[str, Any]:
    exact = exact_cache_match(question=question, lang=lang)
    if not exact.get("ok"):
        return exact

    if exact.get("match"):
        ranked = rank_hybrid_results(
            exact_match=exact.get("match"),
            keyword_matches=[],
            semantic_matches=[],
        )
        return {
            "ok": True,
            "decision": ranked.get("decision"),
            "best": ranked.get("best"),
            "pipeline": {
                "exact_hit": True,
                "keyword_count": 0,
                "semantic_count": 0,
            },
        }

    keyword = keyword_cache_match(question=question, lang=lang, limit=5)
    if not keyword.get("ok"):
        return keyword

    semantic = semantic_match_question(
        question=question,
        lang=lang,
        jurisdiction=jurisdiction,
        match_count=5,
        min_trust=0.75,
    )
    if not semantic.get("ok"):
        return semantic

    ranked = rank_hybrid_results(
        exact_match=None,
        keyword_matches=keyword.get("matches", []),
        semantic_matches=semantic.get("matches", []),
    )

    return {
        "ok": True,
        "decision": ranked.get("decision"),
        "best": ranked.get("best"),
        "candidates": ranked.get("candidates", []),
        "pipeline": {
            "exact_hit": False,
            "keyword_count": len(keyword.get("matches", [])),
            "semantic_count": len(semantic.get("matches", [])),
            "normalized_question": exact.get("normalized_question"),
            "canonical_key": exact.get("canonical_key"),
        },
    }
