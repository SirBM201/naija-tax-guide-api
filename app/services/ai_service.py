from __future__ import annotations

"""
AI SERVICE (CANONICAL + EMBEDDINGS + BOOT-SAFE)

Exports:
- call_ai(...)
- create_embedding(...)

Goals:
- never crash app boot due to missing optional SDKs
- expose clean failure objects instead of throwing
- support both chat generation and embedding creation
"""

import os
from typing import Any, Dict, List, Optional


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _clip(s: Any, n: int = 280) -> str:
    t = str(s or "")
    return t if len(t) <= n else t[:n] + "…"


def _debug_enabled() -> bool:
    return _truthy(_env("AI_DEBUG", "0")) or _truthy(_env("DEBUG", "0"))


def _dbg(msg: str) -> None:
    if _debug_enabled():
        print(msg, flush=True)


def _get_openai_model() -> str:
    return _env("OPENAI_MODEL", _env("AI_MODEL", "gpt-4o-mini"))


def _get_openai_embedding_model() -> str:
    return _env("OPENAI_EMBEDDING_MODEL", "text-embedding-3-small")


def _has_openai_key() -> bool:
    return bool(_env("OPENAI_API_KEY"))


def _import_openai_client():
    try:
        from openai import OpenAI  # type: ignore
        return OpenAI, None
    except Exception as e:
        return None, {
            "ok": False,
            "error": "openai_sdk_missing",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
            "fix": "Install the OpenAI SDK in your backend environment.",
        }


def call_ai(
    *,
    question: str,
    lang: str = "en",
    channel: str = "web",
    system_prompt: Optional[str] = None,
    max_tokens: int = 700,
) -> Dict[str, Any]:
    """
    Canonical answer generator expected by ask_service.

    Returns:
      { ok: True, answer: "...", provider: "openai", model: "..." }
      { ok: False, error: "...", root_cause: "...", fix: "..." }
    """
    q = (question or "").strip()
    if not q:
        return {
            "ok": False,
            "error": "question_required",
            "root_cause": "question_empty",
            "fix": "Pass a non-empty question string.",
        }

    if not _has_openai_key():
        return {
            "ok": False,
            "error": "ai_not_configured",
            "root_cause": "OPENAI_API_KEY is missing.",
            "fix": "Set OPENAI_API_KEY in backend environment variables.",
            "details": {"lang": lang, "channel": channel},
        }

    OpenAI, err = _import_openai_client()
    if err:
        return err

    model = _get_openai_model()
    api_key = _env("OPENAI_API_KEY")

    sys = system_prompt or (
        "You are Naija Tax Guide, an AI assistant focused on Nigerian tax guidance. "
        "Answer clearly, practically, and cautiously. "
        "If a question depends on changing regulations or missing facts, say what is needed."
    )

    try:
        client = OpenAI(api_key=api_key)

        try:
            resp = client.responses.create(
                model=model,
                input=[
                    {"role": "system", "content": sys},
                    {"role": "user", "content": q},
                ],
                max_output_tokens=int(max_tokens or 700),
            )
            answer = getattr(resp, "output_text", None)
            if not answer:
                answer = str(resp)
        except Exception:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": sys},
                    {"role": "user", "content": q},
                ],
                max_tokens=int(max_tokens or 700),
            )
            answer = (resp.choices[0].message.content or "").strip()

        answer = (answer or "").strip()
        if not answer:
            return {
                "ok": False,
                "error": "ai_empty_answer",
                "root_cause": "provider_returned_empty_answer",
                "fix": "Check provider status, model name, and parsing logic.",
                "details": {"model": model, "lang": lang, "channel": channel},
            }

        return {
            "ok": True,
            "answer": answer,
            "provider": "openai",
            "model": model,
        }

    except Exception as e:
        return {
            "ok": False,
            "error": "ai_call_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
            "fix": "Check OPENAI_API_KEY, model access, network, and billing status.",
            "details": {"model": model, "lang": lang, "channel": channel},
        }


def create_embedding(text: str) -> Dict[str, Any]:
    """
    Canonical embedding generator for semantic cache.

    Returns:
      { ok: True, embedding: [...], provider: "openai", model: "..." }
      { ok: False, error: "...", root_cause: "...", fix: "..." }
    """
    content = (text or "").strip()
    if not content:
        return {
            "ok": False,
            "error": "embedding_text_required",
            "root_cause": "text_empty",
            "fix": "Pass non-empty text into create_embedding(text).",
        }

    if not _has_openai_key():
        return {
            "ok": False,
            "error": "embedding_not_configured",
            "root_cause": "OPENAI_API_KEY is missing.",
            "fix": "Set OPENAI_API_KEY in backend environment variables.",
        }

    OpenAI, err = _import_openai_client()
    if err:
        return err

    model = _get_openai_embedding_model()
    api_key = _env("OPENAI_API_KEY")

    try:
        client = OpenAI(api_key=api_key)
        resp = client.embeddings.create(
            model=model,
            input=content,
        )

        data = getattr(resp, "data", None) or []
        if not data:
            return {
                "ok": False,
                "error": "embedding_empty",
                "root_cause": "provider_returned_no_embedding_data",
                "fix": "Check embedding model access and request payload.",
                "details": {"model": model},
            }

        embedding = getattr(data[0], "embedding", None)
        if not embedding:
            try:
                embedding = data[0]["embedding"]
            except Exception:
                embedding = None

        if not embedding:
            return {
                "ok": False,
                "error": "embedding_missing",
                "root_cause": "embedding_vector_missing_in_provider_response",
                "fix": "Inspect provider response shape and SDK version.",
                "details": {"model": model},
            }

        return {
            "ok": True,
            "embedding": embedding,
            "provider": "openai",
            "model": model,
            "dimensions": len(embedding),
        }

    except Exception as e:
        return {
            "ok": False,
            "error": "embedding_create_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
            "fix": "Check OPENAI_API_KEY, embedding model access, network, and billing status.",
            "details": {"model": model},
        }


# Backward-safe aliases
def ask_ai(*args, **kwargs) -> Dict[str, Any]:
    return call_ai(*args, **kwargs)


def generate_ai_answer(*args, **kwargs) -> Dict[str, Any]:
    return call_ai(*args, **kwargs)
