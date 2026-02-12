# app/services/lang_service.py
from __future__ import annotations
import re
from typing import Optional, List

SUPPORTED = {"en", "yo", "ig", "ha", "pcm"}

def normalize_lang(lang: Optional[str]) -> str:
    l = (lang or "").strip().lower()
    if l in ("yoruba", "yo"):
        return "yo"
    if l in ("igbo", "ig"):
        return "ig"
    if l in ("hausa", "ha"):
        return "ha"
    if l in ("pidgin", "pcm", "pigin"):
        return "pcm"
    return "en" if l not in SUPPORTED else l

# Simple low-cost heuristic (better than nothing; WhatsApp/Telegram can pass lang later)
_YO_HINT = re.compile(r"\b(kí|kini|ẹ|ọba|jẹ|fẹ|jọ̀wọ́|ọwọ)\b", re.IGNORECASE)
_HA_HINT = re.compile(r"\b(ina|yaya|me yasa|don|na|kai|ku)\b", re.IGNORECASE)
_IG_HINT = re.compile(r"\b(kedu|biko|anyị|ụlọ|ego)\b", re.IGNORECASE)

def detect_lang(text: str) -> str:
    t = (text or "").lower()
    if _YO_HINT.search(t):
        return "yo"
    if _IG_HINT.search(t):
        return "ig"
    if _HA_HINT.search(t):
        return "ha"
    return "en"

def LANG_FALLBACK_ORDER(preferred: str) -> List[str]:
    p = normalize_lang(preferred)
    if p == "en":
        return ["en"]
    # You can tune this order
    return [p, "en"]
