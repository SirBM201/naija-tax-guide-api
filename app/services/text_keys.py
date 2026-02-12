from __future__ import annotations
import re
from typing import Optional

def _clean(s: str) -> str:
    s = (s or "").lower().strip()
    s = re.sub(r"[^a-z0-9\s]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def canonicalize_question(question: str, lang: Optional[str] = "en") -> str:
    """
    Canonical key rules (EN):
      - normalize punctuation/space
      - map short acronyms: "vat" -> "what is vat"
      - normalize "what's/whats/define/meaning of" -> "what is ..."
      - join with underscores
    For non-EN, we still normalize similarly, but language matching is primarily via qa_aliases.
    """
    s = _clean(question)

    if not s:
        return ""

    # English intent normalization
    if (lang or "en") == "en":
        # acronym-only (2..6 chars) -> treat as definition query
        if re.fullmatch(r"[a-z]{2,6}", s):
            s = f"what is {s}"

        s = re.sub(r"^(what is|whats|what s|define|meaning of)\s+", "what is ", s)

    # underscores
    return re.sub(r"\s+", "_", s)
