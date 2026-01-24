# app/core/text.py
import re

_ws = re.compile(r"\s+")

def normalize_question(q: str) -> str:
    q = (q or "").strip().lower()
    q = _ws.sub(" ", q)
    # keep letters/numbers/basic punctuation; remove weird characters
    q = re.sub(r"[^\w\s\?\.\,\-\/\(\)\:]", "", q)
    return q.strip()
