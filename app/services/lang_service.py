# app/services/lang_service.py
from __future__ import annotations
import re
from typing import Optional

SUPPORTED = ("en", "pcm", "yo", "ig", "ha")

# Lightweight, rule-based detection (NO AI cost)
_YO_MARKERS = {"jẹ", "ọba", "gbọ", "ṣé", "kí", "nítorí", "àti", "wọ́n", "mi", "rẹ", "ń"}
_IG_MARKERS = {"anyị", "gịnị", "ụlọ", "anyị", "n'ụzọ", "ọrụ", "ego", "nke", "na", "ụzọ"}
_HA_MARKERS = {"ina", "me", "ya", "kudi", "haraji", "yaya", "ta", "na", "shi", "kai"}
_PCM_MARKERS = {"wetin", "how far", "abeg", "na", "dey", "wey", "una", "pikin", "no be", "sha"}

def normalize_lang(lang: Optional[str]) -> str:
    if not lang:
        return "en"
    l = lang.strip().lower()

    # normalize common aliases
    alias = {
        "english": "en",
        "en-us": "en", "en-gb": "en",
        "yoruba": "yo", "yo-ng": "yo",
        "igbo": "ig", "ig-ng": "ig",
        "hausa": "ha", "ha-ng": "ha",
        "pidgin": "pcm", "naija": "pcm", "nigerian pidgin": "pcm",
    }.get(l, l)

    return alias if alias in SUPPORTED else "en"

def detect_lang(text: str) -> str:
    t = (text or "").strip().lower()
    if not t:
        return "en"

    # quick pidgin phrase check
    for m in _PCM_MARKERS:
        if m in t:
            return "pcm"

    # token marker checks
    tokens = set(re.findall(r"[a-zA-ZÀ-ž'ọ̀ṣẹ́ụ̀ń]+", t))

    if tokens & _YO_MARKERS:
        return "yo"
    if tokens & _IG_MARKERS:
        return "ig"
    if tokens & _HA_MARKERS:
        return "ha"

    return "en"
