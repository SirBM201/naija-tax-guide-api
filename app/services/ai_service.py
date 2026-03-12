from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

try:
    from openai import OpenAI
except Exception:  # pragma: no cover
    OpenAI = None  # type: ignore


def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _clip(text: str, n: int = 400) -> str:
    text = _safe_str(text)
    return text if len(text) <= n else text[:n] + "…"


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _env(*names: str, default: str = "") -> str:
    for name in names:
        v = os.getenv(name)
        if v and str(v).strip():
            return str(v).strip()
    return default


def _get_model() -> str:
    return _env(
        "OPENAI_MODEL",
        "OPENAI_CHAT_MODEL",
        "AI_MODEL",
        default="gpt-4o-mini",
    )


def _get_api_key() -> str:
    return _env(
        "OPENAI_API_KEY",
        "AI_API_KEY",
        default="",
    )


def _build_client() -> OpenAI:
    if OpenAI is None:
        raise RuntimeError("openai_sdk_missing")

    api_key = _get_api_key()
    if not api_key:
        raise RuntimeError("openai_api_key_not_set")

    return OpenAI(api_key=api_key)


def _default_system_prompt(channel: str = "web") -> str:
    return (
        "You are Naija Tax Guide, a Nigerian tax assistant. "
        "Answer only within Nigerian tax context unless the user explicitly asks otherwise. "
        "Be practical, direct, and accurate. "
        "Do not invent legal citations, deadlines, rates, penalties, or regulatory procedures. "
        "If you are not sure, say so clearly. "
        "If the user asks for a definition, answer with the definition first. "
        "If the user asks for procedure, provide steps where appropriate."
    )


def _call_openai_chat(
    *,
    system_prompt: str,
    user_prompt: str,
    temperature: float = 0.2,
) -> str:
    client = _build_client()
    model = _get_model()

    response = client.chat.completions.create(
        model=model,
        temperature=temperature,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    )

    text = ""
    try:
        text = response.choices[0].message.content or ""
    except Exception:
        text = ""

    text = _safe_str(text)
    if not text:
        raise RuntimeError("openai_empty_answer")

    return text


def call_ai(
    *,
    question: str,
    lang: str = "en",
    channel: str = "web",
    system_prompt: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Backward-compatible AI entry point used by the current repo.

    Returns:
    {
      "ok": True,
      "answer": "...",
      "provider": "openai",
      "model": "gpt-4o-mini"
    }

    or a structured failure:
    {
      "ok": False,
      "error": "...",
      "root_cause": "...",
      "fix": "..."
    }
    """
    question = _safe_str(question)
    if not question:
        return {
            "ok": False,
            "error": "question_required",
            "root_cause": "missing_question",
            "fix": "Provide a non-empty question.",
        }

    prompt = system_prompt or _default_system_prompt(channel)

    try:
        answer = _call_openai_chat(
            system_prompt=prompt,
            user_prompt=question,
            temperature=0.2,
        )
        return {
            "ok": True,
            "answer": answer,
            "provider": "openai",
            "model": _get_model(),
            "lang": lang,
            "channel": channel,
        }
    except Exception as e:
        err = _safe_str(str(e)) or type(e).__name__

        fix = "Check OPENAI_API_KEY and OpenAI package installation."
        if "openai_api_key_not_set" in err:
            fix = "Set OPENAI_API_KEY in your backend environment."
        elif "openai_sdk_missing" in err:
            fix = "Add the OpenAI SDK to requirements.txt and redeploy."
        elif "openai_empty_answer" in err:
            fix = "Inspect provider response and retry."
        elif "authentication" in err.lower() or "api key" in err.lower():
            fix = "Verify the OpenAI API key is valid."
        elif "rate" in err.lower() and "limit" in err.lower():
            fix = "Check provider quota and rate limits."

        return {
            "ok": False,
            "error": "ai_failed",
            "root_cause": err,
            "fix": fix,
        }


def _build_basis(candidates: List[Dict[str, Any]]) -> str:
    blocks: List[str] = []

    for idx, c in enumerate(candidates[:3], start=1):
        answer = _safe_str(c.get("answer"))
        topic = _safe_str(c.get("topic"))
        intent_type = _safe_str(c.get("intent_type"))
        jurisdiction = _safe_str(c.get("jurisdiction"))
        trust_score = c.get("trust_score")
        similarity = c.get("similarity")
        match_type = _safe_str(c.get("match_type"))

        if not answer:
            continue

        blocks.append(
            "\n".join(
                [
                    f"Candidate {idx}:",
                    f"- topic: {topic}",
                    f"- intent_type: {intent_type}",
                    f"- jurisdiction: {jurisdiction}",
                    f"- trust_score: {trust_score}",
                    f"- similarity: {similarity}",
                    f"- match_type: {match_type}",
                    f"- answer: {answer}",
                ]
            )
        )

    return "\n\n".join(blocks) if blocks else "No trusted basis available."


def generate_grounded_answer(
    *,
    question: str,
    lang: str,
    candidates: List[Dict[str, Any]],
    grounding_context: str | None = None,
) -> str:
    """
    Grounded synthesis entry point for the newer architecture.

    If USE_LIVE_GROUNDED_AI is enabled and OpenAI is configured,
    it will try a live grounded synthesis.
    Otherwise it falls back to a controlled local synthesis string.
    """
    question = _safe_str(question)
    basis = _build_basis(candidates)

    use_live_provider = _truthy(os.getenv("USE_LIVE_GROUNDED_AI", ""))

    if use_live_provider and _get_api_key():
        system_prompt = (
            "You are Naija Tax Guide, a grounded Nigerian tax assistant.\n"
            "Answer only within Nigerian tax context.\n"
            "Use only the provided basis and grounding context.\n"
            "Do not invent laws, penalties, filing rules, rates, or deadlines.\n"
            "If the evidence is insufficient, say so clearly.\n"
            "Prefer the strongest matching approved material.\n"
        )

        user_prompt_parts = [
            f"User question:\n{question}",
            "",
            "Grounded basis:",
            basis,
        ]

        if grounding_context:
            user_prompt_parts.extend(
                [
                    "",
                    "Grounding context:",
                    grounding_context,
                ]
            )

        user_prompt_parts.extend(
            [
                "",
                "Write a concise, practical answer for the user.",
            ]
        )

        try:
            return _call_openai_chat(
                system_prompt=system_prompt,
                user_prompt="\n".join(user_prompt_parts),
                temperature=0.1,
            )
        except Exception:
            # Safe fallback below
            pass

    if not candidates:
        return (
            "I do not have enough trusted Nigerian tax material to generate a safe answer for that question yet."
        )

    answer_lines = [
        "Based on the strongest available Nigerian tax guidance in the system, here is the best supported answer:",
        "",
        f"Question: {question}",
        "",
        "Grounded basis:",
        basis,
    ]

    if grounding_context:
        answer_lines.extend(
            [
                "",
                "Grounding context:",
                grounding_context,
            ]
        )

    answer_lines.extend(
        [
            "",
            "Practical guidance:",
            "Use the strongest matching Nigerian tax rule or approved answer above as the basis for your next step. If the situation involves registration, penalties, filing dates, or multi-branch structuring, verify the exact compliance context before acting.",
        ]
    )

    return "\n".join(answer_lines).strip()
