# app/services/ask_service.py
from __future__ import annotations

"""
ASK SERVICE (UPGRADED, FULL FILE)

Goals:
- Uses ONLY canonical identity: accounts.account_id
- exact/canonical cache-first
- strict safe grounding before returning cached answers
- credits only required for uncached / unsafe questions
- friendly no-credit refusal for non-grounded answers
- no patching needed: this file is complete
"""

import os
import re
import uuid
from typing import Any, Dict, Optional

from app.core.supabase_client import supabase
from app.services.ai_service import call_ai
from app.services.credits_service import check_credit_balance
from app.services.qa_cache_service import answer_from_cache, increment_cache_use
from app.services.response_refiner import refine_response, looks_like_ai_failure
from app.services.tax_grounding_service import build_grounded_answer


def _sb():
    return supabase() if callable(supabase) else supabase


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _clip(s: str, n: int = 240) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[:n] + "…"


def _is_uuid(v: str) -> bool:
    try:
        uuid.UUID(str(v))
        return True
    except Exception:
        return False


def _has_column(table: str, col: str) -> bool:
    try:
        _sb().table(table).select(col).limit(1).execute()
        return True
    except Exception:
        return False


def _normalize_question(q: str) -> str:
    q = str(q or "").strip().lower()
    q = re.sub(r"[^\w\s]", " ", q)
    q = re.sub(r"\s+", " ", q).strip()
    return q


def _detect_topic(question: str) -> str:
    q = _normalize_question(question)

    rules = [
        ("vat", ["vat", "value added tax"]),
        ("paye", ["paye", "salary tax", "employee tax", "pay as you earn"]),
        ("withholding_tax", ["withholding tax", "wht"]),
        ("pit", ["personal income tax", "pit"]),
        ("cit", ["company income tax", "cita", "corporate tax"]),
        ("business_registration", ["business registration", "cac", "register business"]),
        ("record_keeping", ["record keeping", "bookkeeping", "receipts", "invoices", "documentation"]),
    ]

    for topic, keys in rules:
        if any(k in q for k in keys):
            return topic
    return "general"


def _detect_intent(question: str) -> str:
    q = _normalize_question(question)

    intent_rules = [
        ("definition", ["what is", "meaning of", "define", "explain"]),
        ("registration", ["register", "registration", "sign up"]),
        ("filing", ["file", "filing", "submit return"]),
        ("calculation", ["calculate", "how much", "rate", "amount"]),
        ("penalty", ["penalty", "fine", "default", "late fee"]),
        ("compliance", ["comply", "compliance", "requirements", "obligation"]),
        ("procedure", ["how do i", "steps", "process", "procedure", "how to"]),
    ]

    for intent, keys in intent_rules:
        if any(k in q for k in keys):
            return intent
    return "general"


def _question_meta(question: str) -> Dict[str, Any]:
    return {
        "topic": _detect_topic(question),
        "intent_type": _detect_intent(question),
        "jurisdiction": "nigeria",
        "normalized_question": _normalize_question(question),
    }


def _enrich_candidate(candidate: Dict[str, Any], question_meta: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(candidate or {})
    out.setdefault("source", "cache")
    out.setdefault("match_type", "exact_cache")
    out.setdefault("review_status", "approved")
    out.setdefault("trust_score", 1.0)
    out.setdefault("jurisdiction", "nigeria")
    out.setdefault("similarity", 1.0)
    out.setdefault("topic", question_meta.get("topic"))
    out.setdefault("intent_type", question_meta.get("intent_type"))
    return out


def resolve_canonical_account_id(raw_account_id: str) -> Dict[str, Any]:
    v = (raw_account_id or "").strip()
    if not v:
        return {
            "ok": False,
            "error": "account_required",
            "root_cause": "missing_account_id",
            "fix": "Provide account_id or authenticate via web cookie/bearer so the server can derive it.",
        }

    if not _is_uuid(v):
        return {
            "ok": False,
            "error": "account_invalid",
            "root_cause": "account_id_not_uuid",
            "fix": "Send a valid UUID for account_id.",
            "details": {"account_id": v},
        }

    if _has_column("accounts", "account_id"):
        try:
            q = _sb().table("accounts").select("id,account_id").eq("account_id", v).limit(1).execute()
            rows = getattr(q, "data", None) or []
            if rows:
                return {"ok": True, "account_id": str(rows[0].get("account_id") or v)}
        except Exception as e:
            return {
                "ok": False,
                "error": "account_lookup_failed",
                "root_cause": f"accounts lookup by account_id failed: {type(e).__name__}: {_clip(str(e))}",
                "fix": "Check Supabase connectivity/RLS for accounts table.",
            }

    try:
        q = _sb().table("accounts").select("id,account_id").eq("id", v).limit(1).execute()
        rows = getattr(q, "data", None) or []
        if not rows:
            return {
                "ok": False,
                "error": "account_not_found",
                "root_cause": "no accounts row matches account_id nor id",
                "fix": "Ensure the account exists. If using web auth, verify OTP first to create/resolve account.",
                "details": {"provided": v},
            }

        row = rows[0] or {}
        canonical = str(row.get("account_id") or "").strip()
        row_id = str(row.get("id") or "").strip()

        if not canonical and row_id:
            try:
                _sb().table("accounts").update({"account_id": row_id}).eq("id", row_id).execute()
                canonical = row_id
            except Exception as e:
                return {
                    "ok": False,
                    "error": "account_id_repair_failed",
                    "root_cause": f"accounts.account_id was NULL and repair failed: {type(e).__name__}: {_clip(str(e))}",
                    "fix": "Run SQL: update accounts set account_id=id where account_id is null; then UNIQUE index on account_id.",
                    "details": {"row_id": row_id},
                }

        if not canonical:
            return {
                "ok": False,
                "error": "account_id_missing",
                "root_cause": "accounts row exists but account_id is empty",
                "fix": "Ensure accounts.account_id exists and is populated.",
                "details": {"row_id": row_id},
            }

        return {"ok": True, "account_id": canonical, "translated_from_id": v}

    except Exception as e:
        return {
            "ok": False,
            "error": "account_lookup_failed",
            "root_cause": f"accounts lookup by id failed: {type(e).__name__}: {_clip(str(e))}",
            "fix": "Check Supabase connectivity/RLS for accounts table.",
        }


def _credit_status(account_id: str) -> Dict[str, Any]:
    bal = check_credit_balance(account_id)
    if bal.get("ok"):
        return {
            "ok": True,
            "credits_available": True,
            "balance": int(bal.get("balance") or 0),
        }

    if bal.get("error") == "insufficient_credits":
        return {
            "ok": True,
            "credits_available": False,
            "balance": int(bal.get("balance") or 0),
        }

    return {
        "ok": False,
        "error": "credit_check_failed",
        "root_cause": bal.get("root_cause") or bal.get("error"),
        "fix": bal.get("fix") or "Fix credits table/RLS.",
        "details": bal.get("details") or {"account_id": account_id},
    }


def _safe_cache_answer(
    *,
    question: str,
    lang: str,
    question_meta: Dict[str, Any],
    credits_available: bool,
) -> Optional[Dict[str, Any]]:
    cached = answer_from_cache(question, lang=lang)
    if not cached:
        return None

    candidate = _enrich_candidate(cached, question_meta)
    grounded = build_grounded_answer(question_meta=question_meta, candidate=candidate)
    refined = refine_response(
        question_meta=question_meta,
        candidate=candidate,
        grounded_result=grounded.__dict__,
        credits_available=credits_available,
    )

    if refined.get("allowed"):
        try:
            increment_cache_use(cached.get("id"))
        except Exception:
            pass

        return {
            "ok": True,
            "answer": refined.get("answer"),
            "from_cache": True,
            "source": refined.get("source") or "cache",
            "confidence": refined.get("confidence"),
            "authority_score": refined.get("authority_score"),
            "grounding_mode": refined.get("grounding_mode"),
            "evidence": refined.get("evidence") or [],
        }

    return {
        "ok": False,
        "error": refined.get("decision") or "unsafe_cache_candidate",
        "reason": refined.get("reason"),
        "user_message": refined.get("user_message"),
    }


def ask_guarded(body: Dict[str, Any]) -> Dict[str, Any]:
    question = (body.get("question") or "").strip()
    if not question:
        return {
            "ok": False,
            "error": "question_required",
            "root_cause": "missing_question",
            "fix": "Provide a non-empty question string.",
        }

    raw_account_id = (body.get("account_id") or "").strip()
    resolved = resolve_canonical_account_id(raw_account_id)
    if not resolved.get("ok"):
        return resolved

    account_id = str(resolved["account_id"]).strip()
    lang = (body.get("lang") or "en").strip() or "en"
    channel = (body.get("channel") or "web").strip() or "web"
    bypass = bool(body.get("__bypass"))
    question_meta = _question_meta(question)

    translation_debug: Dict[str, Any] = {}
    if resolved.get("translated_from_id"):
        translation_debug = {
            "note": "legacy accounts.id was supplied; translated to canonical accounts.account_id",
            "translated_from_id": resolved.get("translated_from_id"),
        }

    if bypass and not _truthy(os.getenv("ALLOW_DEV_BYPASS", "1")):
        return {
            "ok": False,
            "error": "bypass_disabled",
            "root_cause": "__bypass provided but ALLOW_DEV_BYPASS=0",
            "fix": "Remove bypass headers or set ALLOW_DEV_BYPASS=1 in backend env.",
        }

    credits_status = {"ok": True, "credits_available": True, "balance": 999999}
    if not bypass:
        credits_status = _credit_status(account_id)
        if not credits_status.get("ok"):
            return {
                "ok": False,
                "error": credits_status.get("error") or "credit_check_failed",
                "root_cause": credits_status.get("root_cause"),
                "fix": credits_status.get("fix"),
                "details": credits_status.get("details"),
                "debug": {**translation_debug},
            }

    credits_available = bool(credits_status.get("credits_available"))

    cache_result = _safe_cache_answer(
        question=question,
        lang=lang,
        question_meta=question_meta,
        credits_available=credits_available,
    )
    if cache_result and cache_result.get("ok"):
        return {
            "ok": True,
            "answer": cache_result.get("answer"),
            "from_cache": True,
            "account_id": account_id,
            "meta": {
                "source": cache_result.get("source"),
                "confidence": cache_result.get("confidence"),
                "authority_score": cache_result.get("authority_score"),
                "grounding_mode": cache_result.get("grounding_mode"),
                "topic": question_meta.get("topic"),
                "intent_type": question_meta.get("intent_type"),
                "jurisdiction": question_meta.get("jurisdiction"),
            },
            "debug": {**translation_debug},
        }

    if not credits_available:
        return {
            "ok": False,
            "error": "insufficient_credits",
            "root_cause": "ai_credits_balance_zero_and_no_safe_cache_answer",
            "fix": "Top up credits or subscribe to a plan that includes AI credits.",
            "details": {
                "account_id": account_id,
                "balance": int(credits_status.get("balance") or 0),
                "topic": question_meta.get("topic"),
                "intent_type": question_meta.get("intent_type"),
            },
            "message": (
                (cache_result or {}).get("user_message")
                or "Your available AI usage for this period is exhausted, and I do not have a sufficiently reliable cached answer for this question yet."
            ),
            "debug": {**translation_debug},
        }

    try:
        ai = call_ai(
            question=question,
            lang=lang,
            channel=channel,
            system_prompt=(
                "You are Naija Tax Guide. Answer only in Nigerian tax context. "
                "Be direct, practical, and accurate. "
                "If the question asks for procedure, provide steps. "
                "If the question asks for a definition, answer with a definition first. "
                "Do not invent legal citations, rates, deadlines, or penalties."
            ),
        )
    except Exception as e:
        return {
            "ok": False,
            "error": "ai_call_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check AI provider keys, network access, and ai_service configuration.",
            "details": {"account_id": account_id},
            "debug": {**translation_debug},
        }

    if not isinstance(ai, dict) or not ai.get("ok"):
        return {
            "ok": False,
            "error": "ai_failed",
            "root_cause": (ai or {}).get("root_cause") or (ai or {}).get("error") or "unknown_ai_failure",
            "fix": (ai or {}).get("fix") or "Inspect ai_service logs.",
            "details": {"account_id": account_id},
            "debug": {**translation_debug},
        }

    ai_answer = str(ai.get("answer") or "").strip()
    if not ai_answer or looks_like_ai_failure(ai_answer):
        return {
            "ok": False,
            "error": "ai_failed",
            "root_cause": "AI returned an invalid or failure-like answer",
            "fix": "Check AI provider response quality and configuration.",
            "details": {"account_id": account_id},
            "debug": {**translation_debug},
        }

    return {
        "ok": True,
        "answer": ai_answer,
        "from_cache": False,
        "account_id": account_id,
        "meta": {
            "source": "ai",
            "topic": question_meta.get("topic"),
            "intent_type": question_meta.get("intent_type"),
            "jurisdiction": question_meta.get("jurisdiction"),
        },
        "debug": {**translation_debug},
    }
