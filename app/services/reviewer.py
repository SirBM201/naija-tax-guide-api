# app/services/reviewer.py
import json
import logging
from typing import Dict, Any

from app.services.ai import generate_answer


def review_answer(question: str, answer: str, lang: str = "en") -> Dict[str, Any]:
    """
    Risk reviewer:
      - returns risk: low/medium/high
      - confidence: 0-100
      - auto_promote_ok: bool

    Uses the same OpenAI channel via generate_answer (raw HTTP behind the scenes).
    If anything fails, we default to medium risk (no auto-promotion).
    """
    q = (question or "").strip()
    a = (answer or "").strip()

    if not q or not a:
        return {"ok": True, "risk": "high", "confidence": 0, "auto_promote_ok": False, "reasons": ["empty_input"]}

    prompt = f"""
You are a strict Nigerian tax compliance reviewer.

Review the ANSWER to the QUESTION and return ONLY valid JSON with keys:
- risk: "low" | "medium" | "high"
- confidence: integer 0-100
- auto_promote_ok: true/false
- reasons: array of short strings

Rules:
- High risk if answer could cause wrong legal/tax action, wrong filing/penalty guidance, or contains uncertainty presented as fact.
- Medium risk if it seems plausible but needs human verification or lacks clarity.
- Low risk only if it is safe, general, and clearly cautious (no specific rates/dates unless clearly framed as “check current FIRS/LIRS info”).

QUESTION:
{q}

ANSWER:
{a}
""".strip()

    try:
        raw = generate_answer(prompt, lang=lang)
        if not raw:
            return {"ok": True, "risk": "medium", "confidence": 50, "auto_promote_ok": False, "reasons": ["no_reviewer_output"]}

        # Extract JSON safely
        raw_txt = raw.strip()
        # try direct json
        try:
            data = json.loads(raw_txt)
        except Exception:
            # try to find JSON block
            start = raw_txt.find("{")
            end = raw_txt.rfind("}")
            if start != -1 and end != -1 and end > start:
                data = json.loads(raw_txt[start : end + 1])
            else:
                return {"ok": True, "risk": "medium", "confidence": 50, "auto_promote_ok": False, "reasons": ["invalid_json"]}

        risk = str(data.get("risk") or "medium").lower()
        conf = int(data.get("confidence") or 0)
        auto_ok = bool(data.get("auto_promote_ok"))

        if risk not in ("low", "medium", "high"):
            risk = "medium"
        if conf < 0:
            conf = 0
        if conf > 100:
            conf = 100

        # Safety gate: only allow auto promote when low + confidence >= 80
        if not (risk == "low" and conf >= 80 and auto_ok):
            auto_ok = False

        reasons = data.get("reasons") or []
        if not isinstance(reasons, list):
            reasons = [str(reasons)[:80]]

        return {"ok": True, "risk": risk, "confidence": conf, "auto_promote_ok": auto_ok, "reasons": reasons[:8]}
    except Exception as e:
        logging.exception("review_answer failed: %s", e)
        return {"ok": True, "risk": "medium", "confidence": 50, "auto_promote_ok": False, "reasons": ["reviewer_exception"]}
