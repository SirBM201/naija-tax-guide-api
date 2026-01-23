# app/services/answers.py
from typing import Any, Dict, Optional
import re

DISCLAIMER = (
    "_Disclaimer: This is general guidance. For binding advice, confirm with FIRS / your State IRS "
    "or a qualified tax professional._"
)

_MD_H_RE = re.compile(r"(?m)^\s{0,3}#{1,6}\s+")
_MD_LIST_RE = re.compile(r"(?m)^\s{0,3}(-|\*|\d+\.)\s+")
_MD_TABLE_RE = re.compile(r"(?m)^\s*\|.+\|\s*$")

def pick_answer(row: Dict[str, Any], lang: str = "en") -> Optional[str]:
    """
    Select best answer column based on lang.
    Priority:
      answer_<lang> then answer then any available
    """
    lang = (lang or "en").strip().lower()
    if lang in ("pidgin", "pigin", "naija", "naija pidgin"):
        lang = "pcm"
    if lang in ("yoruba", "yo"):
        lang = "yo"
    if lang in ("igbo", "ig"):
        lang = "ig"
    if lang in ("hausa", "ha"):
        lang = "ha"

    key_map = {
        "en": "answer_en",
        "pcm": "answer_pcm",
        "yo": "answer_yo",
        "ig": "answer_ig",
        "ha": "answer_ha",
    }

    preferred = key_map.get(lang)
    if preferred and row.get(preferred):
        return str(row.get(preferred) or "").strip()

    if row.get("answer"):
        return str(row.get("answer") or "").strip()

    # fallback: first non-empty answer-like field
    for k in ["answer_en", "answer_pcm", "answer_yo", "answer_ig", "answer_ha"]:
        if row.get(k):
            return str(row.get(k) or "").strip()

    return None

def _clean_md(text: Optional[str]) -> str:
    t = (text or "").strip().replace("\r\n", "\n").replace("\r", "\n")
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()

def _looks_like_markdown(text: str) -> bool:
    t = (text or "").strip()
    if not t:
        return False
    return bool(_MD_H_RE.search(t) or _MD_LIST_RE.search(t) or _MD_TABLE_RE.search(t) or "```" in t or "**" in t or "_" in t)

def format_markdown_answer(question: str, raw_answer: str) -> str:
    q = _clean_md(question)
    a = _clean_md(raw_answer)

    if not a:
        return (
            "### Direct Answer\n"
            "I couldn't generate a reliable answer for that question.\n\n"
            "### What I need from you\n"
            "- Your **state of operation**\n"
            "- Are you an **individual** or a **business**?\n"
            "- What type of income/transaction is involved?\n\n"
            f"{DISCLAIMER}"
        )

    if "Disclaimer:" in a or "_Disclaimer:" in a:
        return a

    if _looks_like_markdown(a):
        return f"{a}\n\n{DISCLAIMER}"

    return (
        f"### Direct Answer\n{a}\n\n"
        "### What to do next\n"
        "- Confirm if this applies to your **state** and your **business type**.\n"
        "- Keep supporting documents (invoices/receipts, bank statements, contracts).\n"
        "- If uncertain, verify with **FIRS / State IRS** before filing.\n\n"
        f"{DISCLAIMER}"
    )

def strip_markdown_for_tts(md: str) -> str:
    t = _clean_md(md)
    t = re.sub(r"```[\s\S]*?```", "", t)
    t = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", t)
    t = re.sub(r"(?m)^\s{0,3}#{1,6}\s+", "", t)
    t = re.sub(r"(?m)^\s{0,3}(-|\*|\d+\.)\s+", "- ", t)
    t = t.replace("**", "").replace("__", "").replace("*", "").replace("_", "")
    t = re.sub(r"\n{3,}", "\n\n", t).strip()
    return t
