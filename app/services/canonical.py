import re

_AMOUNT_RE = re.compile(
    r"(?i)\b(?:₦|ngn|\$|usd|eur|gbp)?\s*\d[\d,]*(?:\.\d+)?\s*(?:k|m|b)?\b"
)
_REF_RE = re.compile(r"(?i)\((?:ref|reference)\s*[^)]*\)")
_MULTI_SPACE_RE = re.compile(r"\s+")

def canonicalize(text: str) -> str:
    if not text:
        return ""
    s = text.strip().lower()

    # remove "(ref ...)"
    s = _REF_RE.sub(" ", s)

    # replace any money/amount pattern
    s = _AMOUNT_RE.sub(" <amount> ", s)

    # remove punctuation (keep letters/numbers/space/< >)
    s = re.sub(r"[^a-z0-9\s<>]", " ", s)

    # collapse spaces
    s = _MULTI_SPACE_RE.sub(" ", s).strip()

    return s
