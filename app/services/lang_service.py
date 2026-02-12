from __future__ import annotations
from typing import Optional

LANG_ALIASES = {
    "en": "en",
    "english": "en",

    "yo": "yo",
    "yoruba": "yo",

    "ig": "ig",
    "igbo": "ig",

    "ha": "ha",
    "hausa": "ha",

    "pcm": "pcm",
    "pidgin": "pcm",
    "naija": "pcm",
    "nigerian pidgin": "pcm",
}

SUPPORTED = {"en", "yo", "ig", "ha", "pcm"}

def normalize_lang(lang: Optional[str]) -> str:
    v = (lang or "").strip().lower()
    if not v:
        return "en"
    v = LANG_ALIASES.get(v, v)
    return v if v in SUPPORTED else "en"

def detect_lang(text: str) -> str:
    """
    Cheap heuristic (offline). Good enough for YO/IG/HA/PCM vs EN.
    If you later want higher accuracy, you can upgrade this without changing resolver logic.
    """
    t = (text or "").strip().lower()
    if not t:
        return "en"

    # Yoruba hints
    yo_tokens = [" ẹni ", " ṣé", " ni?", " kini", "kí ni", "owo ori", "ìjọba", "jẹ́"]
    if any(tok in t for tok in yo_tokens):
        return "yo"

    # Hausa hints
    ha_tokens = [" haraji", " me yasa", " yaya", " gwamnati", " kudin", " shin "]
    if any(tok in t for tok in ha_tokens):
        return "ha"

    # Igbo hints
    ig_tokens = [" ụtụ", " gọọmenti", " kedu", " ego", " òlee", " gịnị"]
    if any(tok in t for tok in ig_tokens):
        return "ig"

    # Pidgin hints
    pcm_tokens = [" wetin", " how far", " abi", " na ", " dey", " no be", " una "]
    if any(tok in t for tok in pcm_tokens):
        return "pcm"

    return "en"
