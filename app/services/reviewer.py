import os
import json
import logging
from typing import Dict, Any, Optional
import requests

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_REVIEW_MODEL = os.getenv("OPENAI_REVIEW_MODEL", os.getenv("OPENAI_MODEL", "gpt-4o-mini")).strip()
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").strip()

# If you want to fully disable auto-promotion even when risk is low:
AUTO_PROMOTE_LOW_RISK = os.getenv("AUTO_PROMOTE_LOW_RISK", "true").lower().strip() in ("1", "true", "yes")


def review_answer(question: str, answer: str, lang: str = "en") -> Dict[str, Any]:
    """
    Returns:
      {
        "ok": True/False,
        "risk": "low"|"medium"|"high",
        "confidence": 0-100,
        "reasons": [...],
        "auto_promote_ok": True/False
      }
    """
    if not OPENAI_API_KEY:
        return {
            "ok": False,
            "risk": "medium",
            "confidence": 0,
            "reasons": ["AI review disabled (OPENAI_API_KEY missing)"],
            "auto_promote_ok": False,
        }

    q = (question or "").strip()
    a = (answer or "").strip()
    if not q or not a:
        return {
            "ok": False,
            "risk": "medium",
            "confidence": 0,
            "reasons": ["Empty question/answer"],
            "auto_promote_ok": False,
        }

    system = (
        "You are a strict compliance reviewer for a Nigeria-focused tax assistant.\n"
        "Your job: classify whether an answer is safe to store in a public knowledge library.\n\n"
        "Mark HIGH risk if the answer:\n"
        "- gives exact legal conclusions, litigation strategy, or aggressive tax planning\n"
        "- contains unclear/uncertain statements without disclaimers\n"
        "- may be wrong due to changing rates/dates or missing official references\n"
        "- advises evasion, fraud, or non-compliance\n\n"
        "Mark MEDIUM if:\n"
        "- mostly correct but needs checking for dates, forms, portals, or exceptions\n"
        "- contains specifics you are not fully sure about\n\n"
        "Mark LOW if:\n"
        "- it is general educational guidance (definitions, high-level steps)\n"
        "- it includes safe disclaimers and does not overclaim\n\n"
        "Output ONLY valid JSON with keys: risk, confidence, reasons, auto_promote_ok.\n"
        "risk must be one of: low, medium, high.\n"
        "confidence is integer 0-100.\n"
        "reasons is a short list.\n"
        "auto_promote_ok must be true only if risk=low and confidence>=80.\n"
    )

    payload = {
        "model": OPENAI_REVIEW_MODEL,
        "temperature": 0.0,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": f"Language={lang}\n\nQUESTION:\n{q}\n\nANSWER:\n{a}"},
        ],
    }

    try:
        r = requests.post(
            f"{OPENAI_BASE_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=20,
        )

        if r.status_code >= 400:
            logging.warning("Review OpenAI error %s: %s", r.status_code, r.text[:300])
            return {"ok": False, "risk": "medium", "confidence": 0, "reasons": ["review_api_error"], "auto_promote_ok": False}

        data = r.json()
        content = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )
        if not content:
            return {"ok": False, "risk": "medium", "confidence": 0, "reasons": ["empty_review_response"], "auto_promote_ok": False}

        # Must be JSON
        parsed = json.loads(content)
        risk = (parsed.get("risk") or "medium").lower()
        confidence = int(parsed.get("confidence") or 0)
        reasons = parsed.get("reasons") or []
        auto_ok = bool(parsed.get("auto_promote_ok"))

        if risk not in ("low", "medium", "high"):
            risk = "medium"
            auto_ok = False

        if not AUTO_PROMOTE_LOW_RISK:
            auto_ok = False

        return {
            "ok": True,
            "risk": risk,
            "confidence": confidence,
            "reasons": reasons,
            "auto_promote_ok": auto_ok,
        }

    except Exception as e:
        logging.exception("Review request failed: %s", e)
        return {"ok": False, "risk": "medium", "confidence": 0, "reasons": ["review_exception"], "auto_promote_ok": False}
