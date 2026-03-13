from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from app.core.supabase_client import supabase
from app.services.query_classifier import classify_query
from app.services.semantic_cache_service import (
    retrieve_ranked_candidates,
    ranked_debug_dump,
)
from app.services.decision_engine import decide_answer_mode
from app.services.answer_composer import (
    compose_ai_answer,
    compose_clarification,
    compose_direct_cache_answer,
    compose_insufficient_uncached,
    compose_rules_engine_answer,
)
from app.services.usage_guard_service import get_ai_usage_state
from app.services.billing_guard_service import get_billing_state
from app.services.ai_service import generate_grounded_answer
from app.services.tax_grounding_service import build_grounded_answer, grounding_prompt_context
from app.services.response_refiner import refine_response
from app.services.tax_rules.vat_rules import can_handle_vat_rule, resolve_vat_rule
from app.services.tax_rules.paye_rules import can_handle_paye_rule, resolve_paye_rule
from app.services.tax_intent_service import classify_tax_intent
from app.services.tax_process_composer import try_compose


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _include_debug() -> bool:
    return _truthy(os.getenv("DEBUG_AI")) or _truthy(os.getenv("SHOW_ASK_DEBUG"))


def _env_int(name: str, default: int) -> int:
    raw = str(os.getenv(name, "")).strip()
    try:
        return int(raw) if raw else default
    except Exception:
        return default


def _tax_kb_enabled() -> bool:
    return _truthy(os.getenv("ENABLE_TAX_KB", "1"))


def _tax_kb_direct_threshold() -> int:
    return _env_int("TAX_KB_DIRECT_THRESHOLD", 60)


def _tax_kb_result_limit() -> int:
    return _env_int("TAX_KB_RESULT_LIMIT", 3)


def _sb():
    return supabase() if callable(supabase) else supabase


def _normalize_text(value: str) -> str:
    text = (value or "").strip().lower()
    text = re.sub(r"[^a-z0-9\s]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _tokenize(value: str) -> List[str]:
    text = _normalize_text(value)
    if not text:
        return []
    return [t for t in text.split(" ") if t]


def _candidate_to_dict(c) -> Dict[str, Any]:
    if isinstance(c, dict):
        return c

    return {
        "candidate_id": c.candidate_id,
        "question": c.question,
        "answer": c.answer,
        "canonical_key": c.canonical_key,
        "intent_type": c.intent_type,
        "topic": c.topic,
        "jurisdiction": c.jurisdiction,
        "lang": c.lang,
        "trust_score": c.trust_score,
        "review_status": c.review_status,
        "source_authority_score": c.source_authority_score,
        "authority_score": c.source_authority_score,
        "similarity": c.similarity,
        "match_type": c.match_type,
        "rank_score": c.rank_score,
        "source": "cache",
    }


def _classification_to_meta(classification) -> Dict[str, Any]:
    return {
        "topic": classification.topic,
        "intent_type": classification.intent_type,
        "jurisdiction": classification.jurisdiction or "nigeria",
        "complexity": classification.complexity,
        "risk_level": classification.risk_level,
        "normalized_question": classification.normalized_question,
        "canonical_key": classification.canonical_key,
    }


def _resolve_rules(question: str, topic: str, intent_type: str) -> Optional[str]:
    if can_handle_vat_rule(question, topic, intent_type):
        return resolve_vat_rule(question, intent_type)

    if can_handle_paye_rule(question, topic, intent_type):
        return resolve_paye_rule(question, intent_type)

    return None


def _try_process_composer(question: str) -> Optional[Dict[str, Any]]:
    """
    Deterministic process routing layer.
    Handles questions like:
    - how do i pay tax
    - how to register tin
    - how to file tax
    """
    intent = classify_tax_intent(question)

    if not intent:
        return None

    composed = try_compose(intent)

    if not composed:
        return None

    answer = str(composed.get("answer") or "").strip()
    if not answer:
        return None

    meta = composed.get("meta") or {}

    return {
        "answer": answer,
        "meta": meta,
        "intent": intent,
    }


def _filtered_debug(debug: Dict[str, Any]) -> Dict[str, Any]:
    if _include_debug():
        return debug
    return {}


def _topic_matches(classification, row: Dict[str, Any]) -> bool:
    row_topic = str(row.get("topic") or "").strip().lower()
    cls_topic = str(classification.topic or "").strip().lower()
    return bool(row_topic and cls_topic and row_topic == cls_topic)


def _intent_matches(classification, row: Dict[str, Any]) -> bool:
    row_intent = str(row.get("intent_type") or "").strip().lower()
    cls_intent = str(classification.intent_type or "").strip().lower()
    return bool(row_intent and cls_intent and row_intent == cls_intent)


def _jurisdiction_matches(classification, row: Dict[str, Any]) -> bool:
    row_j = str(row.get("jurisdiction") or "").strip().lower()
    cls_j = str(classification.jurisdiction or "nigeria").strip().lower()
    if not row_j:
        return True
    return row_j == cls_j


def _score_tax_chunk(question: str, classification, row: Dict[str, Any]) -> Dict[str, Any]:
    score = 0
    reasons: List[str] = []

    normalized_question = _normalize_text(question)
    q_tokens = set(_tokenize(question))

    summary = str(row.get("summary") or "")
    text_content = str(row.get("text_content") or "")
    keywords_raw = row.get("keywords") or []
    if isinstance(keywords_raw, str):
        keywords = [k.strip() for k in keywords_raw.split(",") if k.strip()]
    elif isinstance(keywords_raw, list):
        keywords = [str(k).strip() for k in keywords_raw if str(k).strip()]
    else:
        keywords = []

    searchable_text = " ".join(
        [
            str(row.get("topic") or ""),
            str(row.get("intent_type") or ""),
            summary,
            text_content,
            " ".join(keywords),
        ]
    )
    normalized_searchable = _normalize_text(searchable_text)
    searchable_tokens = set(_tokenize(searchable_text))

    if _topic_matches(classification, row):
        score += 35
        reasons.append("topic_match:+35")

    if _intent_matches(classification, row):
        score += 18
        reasons.append("intent_match:+18")

    if _jurisdiction_matches(classification, row):
        reasons.append("jurisdiction_ok")

    summary_norm = _normalize_text(summary)
    if summary_norm:
        if summary_norm in normalized_question or normalized_question in summary_norm:
            score += 20
            reasons.append("summary_match:+20")
        else:
            summary_tokens = set(_tokenize(summary))
            overlap = len(q_tokens.intersection(summary_tokens))
            if overlap >= 2:
                score += 20
                reasons.append("summary_overlap:+20")

    keyword_hits = 0
    for kw in keywords:
        kw_norm = _normalize_text(kw)
        if kw_norm and kw_norm in normalized_question:
            keyword_hits += 1
    if keyword_hits > 0:
        score += 8
        reasons.append(f"keyword_match:+8 ({keyword_hits} hits)")

    overlap_tokens = len(q_tokens.intersection(searchable_tokens))
    if overlap_tokens > 0:
        overlap_bonus = min(overlap_tokens * 3, 15)
        score += overlap_bonus
        reasons.append(f"token_overlap:+{overlap_bonus}")

    if normalized_question and normalized_question in normalized_searchable:
        score += 6
        reasons.append("phrase_hit:+6")

    score = min(score, 100)

    return {
        "score": score,
        "reasons": reasons,
        "matched_keywords": [kw for kw in keywords if _normalize_text(kw) in normalized_question],
    }


def _fetch_tax_kb_rows(limit: int = 200) -> List[Dict[str, Any]]:
    try:
        client = _sb()
        response = (
            client.table("tax_source_chunks")
            .select(
                "chunk_id, source_id, topic, intent_type, jurisdiction, text_content, summary, keywords"
            )
            .limit(limit)
            .execute()
        )
        rows = getattr(response, "data", None) or []
        return rows if isinstance(rows, list) else []
    except Exception:
        return []


def _fetch_source_titles() -> Dict[str, str]:
    try:
        client = _sb()
        response = client.table("tax_source_registry").select("source_id, title").execute()
        rows = getattr(response, "data", None) or []
        if not isinstance(rows, list):
            return {}
        return {
            str(r.get("source_id")): str(r.get("title") or r.get("source_id") or "").strip()
            for r in rows
            if r.get("source_id")
        }
    except Exception:
        return {}


def _retrieve_tax_knowledge_matches(question: str, classification) -> List[Dict[str, Any]]:
    if not _tax_kb_enabled():
        return []

    rows = _fetch_tax_kb_rows(limit=300)
    if not rows:
        return []

    source_titles = _fetch_source_titles()
    scored: List[Dict[str, Any]] = []

    for row in rows:
        if not _jurisdiction_matches(classification, row):
            continue

        score_info = _score_tax_chunk(question, classification, row)
        if score_info["score"] <= 0:
            continue

        enriched = {
            "chunk_id": row.get("chunk_id"),
            "source_id": row.get("source_id"),
            "source_title": source_titles.get(
                str(row.get("source_id") or ""),
                str(row.get("source_id") or "Official Tax Source"),
            ),
            "topic": row.get("topic"),
            "intent_type": row.get("intent_type"),
            "jurisdiction": row.get("jurisdiction") or "nigeria",
            "text_content": row.get("text_content") or "",
            "summary": row.get("summary") or "",
            "keywords": row.get("keywords") or [],
            "score": score_info["score"],
            "score_reasons": score_info["reasons"],
            "matched_keywords": score_info["matched_keywords"],
            "source": "tax_kb",
        }
        scored.append(enriched)

    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[: _tax_kb_result_limit()]


def _tax_match_to_candidate(match: Dict[str, Any]) -> Dict[str, Any]:
    answer_text = str(match.get("text_content") or "").strip()
    source_title = str(match.get("source_title") or "Official Tax Source").strip()

    if source_title and source_title not in answer_text:
        answer_text = f"{answer_text}\n\nSource: {source_title}"

    return {
        "candidate_id": match.get("chunk_id"),
        "question": match.get("summary") or match.get("chunk_id"),
        "answer": answer_text,
        "canonical_key": match.get("chunk_id"),
        "intent_type": match.get("intent_type"),
        "topic": match.get("topic"),
        "jurisdiction": match.get("jurisdiction") or "nigeria",
        "lang": "en",
        "trust_score": 1.0,
        "review_status": "approved",
        "source_authority_score": 1.0,
        "authority_score": 1.0,
        "similarity": float(match.get("score") or 0) / 100.0,
        "match_type": "tax_kb",
        "rank_score": match.get("score") or 0,
        "source": "tax_kb",
        "source_title": source_title,
        "summary": match.get("summary") or "",
        "keywords": match.get("keywords") or [],
        "text_content": match.get("text_content") or "",
    }


def _build_tax_grounding_context(
    *,
    question_meta: Dict[str, Any],
    tax_matches: List[Dict[str, Any]],
) -> Optional[str]:
    if not tax_matches:
        return None

    lines: List[str] = []
    lines.append("OFFICIAL NIGERIAN TAX KNOWLEDGE")
    lines.append(f"Topic: {question_meta.get('topic')}")
    lines.append(f"Intent: {question_meta.get('intent_type')}")
    lines.append("Use the evidence below as the highest-priority grounding source.")
    lines.append("Do not contradict these source-backed tax statements.")
    lines.append("")

    for i, match in enumerate(tax_matches, start=1):
        lines.append(f"[SOURCE {i}]")
        lines.append(f"Source ID: {match.get('source_id')}")
        lines.append(f"Source Title: {match.get('source_title')}")
        lines.append(f"Chunk ID: {match.get('chunk_id')}")
        lines.append(f"Topic: {match.get('topic')}")
        lines.append(f"Intent: {match.get('intent_type')}")
        lines.append(f"Summary: {match.get('summary')}")
        lines.append(f"Text: {match.get('text_content')}")
        lines.append("")

    return "\n".join(lines).strip()


def _try_safe_candidate_answer(
    *,
    candidate,
    question_meta: Dict[str, Any],
    credits_available: bool,
) -> Optional[Dict[str, Any]]:
    if not candidate:
        return None

    candidate_dict = _candidate_to_dict(candidate)

    grounded = build_grounded_answer(
        question_meta=question_meta,
        candidate=candidate_dict,
        composed_answer=candidate_dict.get("answer"),
    )

    grounded_result = grounded.__dict__ if hasattr(grounded, "__dict__") else dict(grounded)

    refined = refine_response(
        question_meta=question_meta,
        candidate=candidate_dict,
        grounded_result=grounded_result,
        credits_available=credits_available,
    )

    if refined.get("allowed"):
        fallback_answer = candidate_dict.get("answer") or ""
        return {
            "allowed": True,
            "answer": str(refined.get("answer") or fallback_answer).strip(),
            "grounded": grounded_result,
            "refined": refined,
        }

    return {
        "allowed": False,
        "grounded": grounded_result,
        "refined": refined,
    }


def ask_guarded(
    *,
    account_id: str,
    question: str,
    lang: str = "en",
    channel: str = "web",
) -> Dict[str, Any]:
    classification = classify_query(question, lang=lang)
    question_meta = _classification_to_meta(classification)

    usage_state = get_ai_usage_state(account_id)
    billing_state = get_billing_state(account_id)
    credits_available = bool(usage_state.get("has_ai_credit"))

    debug: Dict[str, Any] = {
        "classification": classification.__dict__,
        "billing_state": billing_state,
        "usage_state": usage_state,
    }

    # Step 1: clarification gate
    temp_ranked = retrieve_ranked_candidates(classification)
    temp_decision = decide_answer_mode(
        classification,
        temp_ranked,
        has_ai_credit=credits_available,
        monthly_ai_usage=int(usage_state["monthly_ai_usage"]),
        monthly_ai_limit=int(usage_state["monthly_ai_limit"]),
    )

    debug["initial_decision"] = {
        "mode": temp_decision.mode,
        "reasons": temp_decision.reasons,
    }
    debug["ranked_candidates"] = ranked_debug_dump(temp_ranked[:5])

    if temp_decision.mode == "clarification":
        res = compose_clarification(debug=_filtered_debug(debug))
        return res.__dict__

    # Step 2: deterministic tax rules (VAT/PAYE)
    rule_answer = _resolve_rules(question, classification.topic, classification.intent_type)
    if rule_answer:
        debug["final_path"] = "rules_engine"
        res = compose_rules_engine_answer(rule_answer, debug=_filtered_debug(debug))
        return res.__dict__

    # Step 3: deterministic process composers (TIN / tax payment / tax filing)
    process_result = _try_process_composer(question)
    if process_result:
        debug["process_composer"] = {
            "intent": process_result.get("intent"),
            "meta": process_result.get("meta"),
        }
        debug["final_path"] = "process_composer"

        res = compose_rules_engine_answer(
            process_result.get("answer", ""),
            debug=_filtered_debug(debug),
        )
        return res.__dict__

    # Step 4: official tax knowledge retrieval
    tax_matches = _retrieve_tax_knowledge_matches(question, classification)
    debug["tax_matches"] = tax_matches
    debug["tax_candidates"] = [
        {
            "chunk_id": m.get("chunk_id"),
            "source_id": m.get("source_id"),
            "source_title": m.get("source_title"),
            "topic": m.get("topic"),
            "intent_type": m.get("intent_type"),
            "score": m.get("score"),
            "summary": m.get("summary"),
            "matched_keywords": m.get("matched_keywords"),
            "score_reasons": m.get("score_reasons"),
        }
        for m in tax_matches
    ]

    best_tax_match = tax_matches[0] if tax_matches else None
    tax_direct_threshold = _tax_kb_direct_threshold()

    if best_tax_match and int(best_tax_match.get("score") or 0) >= tax_direct_threshold:
        tax_candidate = _tax_match_to_candidate(best_tax_match)

        safe_tax = _try_safe_candidate_answer(
            candidate=tax_candidate,
            question_meta=question_meta,
            credits_available=credits_available,
        )

        debug["tax_grounding_context"] = _build_tax_grounding_context(
            question_meta=question_meta,
            tax_matches=tax_matches,
        )
        debug["tax_direct_threshold"] = tax_direct_threshold
        debug["best_tax_score"] = best_tax_match.get("score")
        debug["final_path"] = "tax_kb_direct"

        if safe_tax and safe_tax.get("allowed"):
            res = compose_rules_engine_answer(
                safe_tax.get("answer", ""),
                debug=_filtered_debug(debug),
            )
            return res.__dict__

    # Step 5: semantic cache retrieval
    ranked = temp_ranked
    decision = decide_answer_mode(
        classification,
        ranked,
        has_ai_credit=credits_available,
        monthly_ai_usage=int(usage_state["monthly_ai_usage"]),
        monthly_ai_limit=int(usage_state["monthly_ai_limit"]),
    )

    debug["decision"] = {
        "mode": decision.mode,
        "reasons": decision.reasons,
    }

    best_candidate = decision.best_candidate or (ranked[0] if ranked else None)

    safe_candidate = _try_safe_candidate_answer(
        candidate=best_candidate,
        question_meta=question_meta,
        credits_available=credits_available,
    )

    if safe_candidate:
        debug["candidate_grounding"] = safe_candidate.get("grounded")
        debug["candidate_refiner"] = safe_candidate.get("refined")

        if safe_candidate.get("allowed"):
            debug["final_path"] = "direct_cache"
            res = compose_direct_cache_answer(
                best_candidate,
                answer_text=safe_candidate.get("answer"),
                debug=_filtered_debug(debug),
            )
            return res.__dict__

    # Step 6: if no AI credit, stop after deterministic + tax direct + cache attempts
    if decision.mode == "insufficient_credits_uncached" or not credits_available:
        debug["final_path"] = "insufficient_uncached"
        res = compose_insufficient_uncached(debug=_filtered_debug(debug))
        return res.__dict__

    # Step 7: grounded AI synthesis using official tax KB + cache evidence
    grounded_candidates = [_candidate_to_dict(c) for c in ranked[:3]]

    grounding_context_parts: List[str] = []

    tax_grounding = _build_tax_grounding_context(
        question_meta=question_meta,
        tax_matches=tax_matches,
    )
    if tax_grounding:
        grounding_context_parts.append(tax_grounding)

    if grounded_candidates:
        grounded_preview = build_grounded_answer(
            question_meta=question_meta,
            candidate=grounded_candidates[0],
            composed_answer=grounded_candidates[0].get("answer"),
        )

        grounded_preview_dict = (
            grounded_preview.__dict__ if hasattr(grounded_preview, "__dict__") else dict(grounded_preview)
        )

        cache_grounding = grounding_prompt_context(
            question_meta=question_meta,
            grounded=grounded_preview,
        )
        if cache_grounding:
            grounding_context_parts.append(cache_grounding)
        debug["grounded_preview"] = grounded_preview_dict

    grounding_context = "\n\n".join([p for p in grounding_context_parts if p]).strip() or None
    debug["tax_grounding_context"] = tax_grounding
    debug["final_path"] = "grounded_synthesis"

    answer_text = generate_grounded_answer(
        question=question,
        lang=lang,
        candidates=grounded_candidates,
        grounding_context=grounding_context,
    )

    res = compose_ai_answer(answer_text, debug=_filtered_debug(debug))
    return res.__dict__
