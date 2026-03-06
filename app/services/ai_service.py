# app/services/ai_service.py
from __future__ import annotations

"""
AI SERVICE (BOOT-SAFE, CANONICAL EXPORTS)

This file MUST NOT crash boot due to missing exports.

Your crash:
  ImportError: cannot import name 'call_ai' from 'app.services.ai_service'

So this module guarantees:
  - call_ai(...) exists (canonical name)
  - call_ai returns a dict: { ok: bool, answer?: str, error?: str, root_cause?: str, fix?: str }

Provider strategy:
  - If OPENAI_API_KEY exists -> try OpenAI (optional dependency-safe)
  - Else -> returns a clear error (so boot still works, and you see what to set)

No matter what, importing this module will NOT crash your app boot.
"""

import os
from typing import Any, Dict, Optional


# -----------------------------
# Helpers
# -----------------------------
def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _clip(s: str, n: int = 280) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[:n] + "…"


def _debug_enabled() -> bool:
    return _truthy(_env("AI_DEBUG", "0")) or _truthy(_env("DEBUG", "0"))


def _dbg(msg: str) -> None:
    if _debug_enabled():
        print(msg, flush=True)


# -----------------------------
# Canonical API
# -----------------------------
def call_ai(
    *,
    question: str,
    lang: str = "en",
    channel: str = "web",
    system_prompt: Optional[str] = None,
    max_tokens: int = 700,
) -> Dict[str, Any]:
    """
    Canonical function expected by ask_service/routes.

    Returns:
      { ok: True, answer: "..." }
      { ok: False, error: "...", root_cause: "...", fix: "..." }
    """
    q = (question or "").strip()
    if not q:
        return {
            "ok": False,
            "error": "question_required",
            "root_cause": "question_empty",
            "fix": "Pass a non-empty question string to call_ai(question=...).",
        }

    # Choose provider
    if _env("OPENAI_API_KEY", ""):
        return _call_openai(
            question=q,
            lang=lang,
            channel=channel,
            system_prompt=system_prompt,
            max_tokens=max_tokens,
        )

    # No provider configured -> boot-safe error
    return {
        "ok": False,
        "error": "ai_not_configured",
        "root_cause": "No AI provider API key is configured on the backend.",
        "fix": (
            "Set one provider key in your backend env. "
            "For OpenAI set OPENAI_API_KEY (and optionally OPENAI_MODEL)."
        ),
        "details": {
            "expected_env": ["OPENAI_API_KEY", "OPENAI_MODEL(optional)"],
            "lang": lang,
            "channel": channel,
        },
    }


# Backwards/alternate names (optional safety)
def ask_ai(*args, **kwargs) -> Dict[str, Any]:
    """Alias for older code paths."""
    return call_ai(*args, **kwargs)


def generate_ai_answer(*args, **kwargs) -> Dict[str, Any]:
    """Alias for older code paths."""
    return call_ai(*args, **kwargs)


# -----------------------------
# OpenAI implementation (dependency-safe)
# -----------------------------
def _call_openai(
    *,
    question: str,
    lang: str,
    channel: str,
    system_prompt: Optional[str],
    max_tokens: int,
) -> Dict[str, Any]:
    """
    Uses OpenAI if the SDK is installed.
    If the SDK isn't installed, returns a clear error (still boot-safe).
    """
    api_key = _env("OPENAI_API_KEY", "")
    model = _env("OPENAI_MODEL", _env("AI_MODEL", "gpt-4o-mini"))
    if not api_key:
        return {
            "ok": False,
            "error": "openai_missing_key",
            "root_cause": "OPENAI_API_KEY is empty",
            "fix": "Set OPENAI_API_KEY in backend environment variables.",
        }

    # Import in a try/except so missing dependency never breaks boot
    try:
        from openai import OpenAI  # type: ignore
    except Exception as e:
        return {
            "ok": False,
            "error": "openai_sdk_missing",
            "root_cause": f"OpenAI SDK import failed: {type(e).__name__}: {_clip(str(e))}",
            "fix": "Add openai to requirements.txt (pip install openai) or switch provider implementation.",
        }

    try:
        client = OpenAI(api_key=api_key)

        sys = system_prompt or (
            "You are Naija Tax Guide. Answer clearly, correctly, and concisely. "
            "If unsure, say so and suggest what info is needed."
        )

        # Use Responses API style if available, fallback to ChatCompletions if not.
        # (Keep compatibility and avoid boot-time assumptions.)
        try:
            resp = client.responses.create(
                model=model,
                input=[
                    {"role": "system", "content": sys},
                    {"role": "user", "content": question},
                ],
                max_output_tokens=int(max_tokens or 700),
            )
            # Most SDKs expose output_text
            answer = getattr(resp, "output_text", None)
            if not answer:
                # fallback extraction if needed
                answer = str(resp)
        except Exception:
            # Older style
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": sys},
                    {"role": "user", "content": question},
                ],
                max_tokens=int(max_tokens or 700),
            )
            answer = (resp.choices[0].message.content or "").strip()

        answer = (answer or "").strip()
        if not answer:
            return {
                "ok": False,
                "error": "openai_empty_answer",
                "root_cause": "OpenAI returned empty content.",
                "fix": "Check provider status, model name, and request payload.",
                "details": {"model": model, "lang": lang, "channel": channel},
            }

        return {"ok": True, "answer": answer, "provider": "openai", "model": model}

    except Exception as e:
        return {
            "ok": False,
            "error": "openai_call_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check OPENAI_API_KEY, model name, outbound network access, and OpenAI account status.",
            "details": {"model": model, "lang": lang, "channel": channel},
        }
