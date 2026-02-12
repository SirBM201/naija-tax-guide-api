import re
from typing import Literal

Lang = Literal["en", "yo", "ig", "ha", "pcm"]

_YO_HINT = re.compile(r"(?i)\b(ẹ̀|ọba|ọwọ|jẹ́|ṣé|kíni|jẹ)\b")
_PCM_HINT = re.compile(r"(?i)\b(wetin|abi|dey|na|no be|oya)\b")
_HA_HINT = re.compile(r"(?i)\b(me yasa|ina|yaya|naira|haraji)\b")
_IG_HINT = re.compile(r"(?i)\b(kedu|ego|ụtụ|anyị|ọrụ)\b")

def detect_lang(text: str) -> Lang:
    s = (text or "").strip().lower()
    if not s:
        return "en"
    if _YO_HINT.search(s):
        return "yo"
    if _PCM_HINT.search(s):
        return "pcm"
    if _HA_HINT.search(s):
        return "ha"
    if _IG_HINT.search(s):
        return "ig"
    return "en"

def pick_library_answer(row: dict, lang: Lang) -> str | None:
    # Map to your real column names (based on your screenshots)
    col_map = {
        "en": "answer_en",
        "yo": "answer_yoruba",   # or answer_yo if you used that name
        "ig": "answer_igbo",     # or answer_ig
        "ha": "answer_hausa",    # or answer_ha
        "pcm": "answer_pidgin",
    }

    preferred = col_map.get(lang, "answer_en")
    ans = (row.get(preferred) or "").strip()
    if ans:
        return ans

    # fallback to English
    ans = (row.get("answer_en") or "").strip()
    return ans or None
