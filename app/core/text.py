import re

_ACRONYM_EXPAND = {
    "vat": "what is vat",
    "tin": "what is tin",
    "paye": "what is paye",
    "wht": "what is wht",
}

def normalize_question(q: str) -> str:
    """
    Normalizes user text into a predictable lookup key.
    Also expands common single-word acronyms so your library can match.
    """
    s = (q or "").strip().lower()
    s = re.sub(r"\s+", " ", s)

    # remove surrounding punctuation
    s = s.strip(" \t\r\n.,;:!?\"'()[]{}<>")

    # if user typed only "vat" or "tin", expand it
    if s in _ACRONYM_EXPAND:
        return _ACRONYM_EXPAND[s]

    return s
