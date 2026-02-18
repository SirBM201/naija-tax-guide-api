# app/services/ai_service.py
from __future__ import annotations

import os
from typing import Optional

try:
    from openai import OpenAI  # type: ignore
except Exception:
    OpenAI = None  # type: ignore

_last_error: str = ""


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


SYSTEM_PROMPT = (
    "You are NaijaTax Guide, a practical Nigerian tax assistant.\n"
    "Give clear, step-by-step explanations. Use Nigerian context.\n"
    "If assumptions are needed, state them. Avoid legal disclaimers unless necessary.\n"
)


def _set_last_error(msg: str) -> None:
    global _last_error
    _last_error = (msg or "").strip()


def last_ai_error() -> str:
    return _last_error


def _get_client() -> Optional["OpenAI"]:
    api_key = _env("OPENAI_API_KEY", "")
    if not api_key:
        _set_last_error("OPENAI_API_KEY not set")
        return None
    if OpenAI is None:
        _set_last_error("openai package not installed")
        return None
    return OpenAI(api_key=api_key)


def ask_ai(question: str, lang: str = "en") -> Optional[str]:
    """Single-turn ask."""
    client = _get_client()
    if client is None:
        return None

    model = _env("OPENAI_MODEL", "gpt-4o-mini")
    prompt = f"{SYSTEM_PROMPT}\n\n[Language: {lang}]\n\nUser question:\n{question}".strip()

    try:
        resp = client.responses.create(
            model=model,
            input=prompt,
            temperature=0.3,
        )

        out = getattr(resp, "output", None)
        if not out:
            _set_last_error("No output from model")
            return None

        for item in out:
            if getattr(item, "type", None) == "message":
                for c in (getattr(item, "content", None) or []):
                    if getattr(c, "type", None) == "output_text":
                        text = (getattr(c, "text", "") or "").strip()
                        if text:
                            _set_last_error("")
                            return text

        _set_last_error("No output_text content found")
        return None

    except Exception as e:
        msg = str(e).lower()

        if "401" in msg or "unauthorized" in msg or "invalid_api_key" in msg:
            _set_last_error("OpenAI 401 Unauthorized (check OPENAI_API_KEY in Koyeb env vars)")
            return None

        if "429" in msg or "rate limit" in msg or "quota" in msg:
            _set_last_error("OpenAI rate/quota limit reached (429). Try again later.")
            return None

        if "timeout" in msg:
            _set_last_error("OpenAI request timed out. Try again.")
            return None

        _set_last_error(f"OpenAI request failed: {type(e).__name__}")
        return None


def ask_ai_chat(messages: list[dict[str, str]], lang: str = "en") -> Optional[str]:
    """Chat-style AI call. messages: [{role, content}]"""

    client = _get_client()
    if client is None:
        return None

    model = _env("OPENAI_MODEL", "gpt-4o-mini")

    cleaned: list[dict[str, str]] = []
    for m in (messages or []):
        role = (m.get("role") or "").strip().lower()
        if role not in {"user", "assistant", "system"}:
            continue
        content = (m.get("content") or "").strip()
        if not content:
            continue
        cleaned.append({"role": role, "content": content})

    if not cleaned:
        _set_last_error("empty chat")
        return None

    system = SYSTEM_PROMPT
    if lang:
        system = f"{SYSTEM_PROMPT}\n\n[Language: {lang}]"

    input_msgs = [{"role": "system", "content": system}] + cleaned

    try:
        resp = client.responses.create(
            model=model,
            input=input_msgs,
            temperature=0.3,
        )

        out = getattr(resp, "output", None)
        if not out:
            _set_last_error("No output from model")
            return None

        for item in out:
            if getattr(item, "type", None) == "message":
                for c in (getattr(item, "content", None) or []):
                    if getattr(c, "type", None) == "output_text":
                        text = (getattr(c, "text", "") or "").strip()
                        if text:
                            _set_last_error("")
                            return text

        _set_last_error("No output_text content found")
        return None

    except Exception as e:
        msg = str(e).lower()

        if "401" in msg or "unauthorized" in msg or "invalid_api_key" in msg:
            _set_last_error("OpenAI 401 Unauthorized (check OPENAI_API_KEY in Koyeb env vars)")
            return None

        if "429" in msg or "rate limit" in msg or "quota" in msg:
            _set_last_error("OpenAI rate/quota limit reached (429). Try again later.")
            return None

        if "timeout" in msg:
            _set_last_error("OpenAI request timed out. Try again.")
            return None

        _set_last_error(f"OpenAI request failed: {type(e).__name__}")
        return None

# add to app/services/ai_service.py (keep your existing ask_ai intact)
from typing import List, Dict

def ask_ai_chat(messages: List[Dict[str, str]]) -> str:
    """
    Chat-style call with history.
    messages = [{role:'system'|'user'|'assistant', content:'...'}]
    """
    try:
        # If you already use OpenAI client in this file, reuse it.
        resp = client.responses.create(
            model=MODEL_TEXT,
            input=[{"role": m["role"], "content": [{"type": "input_text", "text": m["content"]}]} for m in messages],
        )
        # best-effort extraction
        out = ""
        for item in getattr(resp, "output", []) or []:
            for c in getattr(item, "content", []) or []:
                if getattr(c, "type", "") in ("output_text", "text") and getattr(c, "text", None):
                    out += c.text
        return (out or "").strip() or "Sorry — I couldn't generate a response right now."
    except Exception as e:
        return "Sorry — the assistant is temporarily unavailable."

