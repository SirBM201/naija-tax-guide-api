# app/services/question_canonicalizer.py
from __future__ import annotations

import re
from typing import Optional, Dict

# -----------------------------
# Basic resources
# -----------------------------
MONTHS = {
    "january": "jan", "jan": "jan",
    "february": "feb", "feb": "feb",
    "march": "mar", "mar": "mar",
    "april": "apr", "apr": "apr",
    "may": "may",
    "june": "jun", "jun": "jun",
    "july": "jul", "jul": "jul",
    "august": "aug", "aug": "aug",
    "september": "sep", "sept": "sep", "sep": "sep",
    "october": "oct", "oct": "oct",
    "november": "nov", "nov": "nov",
    "december": "dec", "dec": "dec",
}

# Nigeria states (lowercased)
NIGERIA_STATES = {
    "abia","adamawa","akwa ibom","anambra","bauchi","bayelsa","benue","borno","cross river","delta","ebonyi",
    "edo","ekiti","enugu","gombe","imo","jigawa","kaduna","kano","katsina","kebbi","kogi","kwara","lagos",
    "nasarawa","niger","ogun","ondo","osun","oyo","plateau","rivers","sokoto","taraba","yobe","zamfara","fct","abuja"
}

STOPWORDS = {
    "the","a","an","and","or","to","for","in","on","at","of","with","from","by","is","are","was","were",
    "i","me","my","we","our","you","your","they","their","it","this","that","these","those","please","pls",
    "how","what","when","where","which","do","does","did","can","should","would","could","kindly"
}

# Intent rules (expandable, deterministic)
INTENTS: Dict[str, list[str]] = {
    "record_keeping": [
        "keep records", "record keeping", "bookkeeping", "documentation", "proof", "evidence",
        "receipts", "invoices", "reconcile", "bank statement", "track income", "track expenses",
    ],
    "paye": ["paye", "salary tax", "employee tax"],
    "vat": ["vat", "value added tax"],
    "pit": ["pit", "personal income tax"],
    "business_reg": ["business registration", "cac", "register business"],
    "withholding_tax": ["withholding tax", "wht"],
    "compliance": ["file", "filing", "compliance", "penalty", "late payment", "audit"],
}

CHANNEL_RULES = {
    "web_chat": ["web chat", "website chat", "live chat", "site chat"],
    "whatsapp": ["whatsapp", "wa"],
    "telegram": ["telegram", "tg"],
    "bank_transfer": ["bank transfer", "transfer"],
    "paypal": ["paypal"],
    "payoneer": ["payoneer"],
    "card": ["card", "debit card", "credit card"],
}

CURRENCY_PATTERN = re.compile(r"(?i)(₦|ngn|naira|\$|usd|eur|€|gbp|£)")
AMOUNT_PATTERN = re.compile(r"(?i)(₦|\$|€|£)?\s*\d[\d,]*")


def _clean_text(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^\w\s]", " ", s)  # remove punctuation
    s = re.sub(r"\s+", " ", s).strip()
    return s


def extract_state(text: str) -> Optional[str]:
    t = _clean_text(text)
    # try exact multi-word states first
    for st in sorted(NIGERIA_STATES, key=len, reverse=True):
        if st in t:
            return "abuja" if st == "fct" else st
    return None


def extract_month(text: str) -> Optional[str]:
    t = _clean_text(text)
    tokens = t.split()
    for tok in tokens:
        if tok in MONTHS:
            return MONTHS[tok]
    return None


def detect_channel(text: str) -> Optional[str]:
    t = _clean_text(text)
    for ch, keys in CHANNEL_RULES.items():
        for k in keys:
            if k in t:
                return ch
    return None


def detect_intent(text: str) -> str:
    t = _clean_text(text)
    for intent, keys in INTENTS.items():
        for k in keys:
            if k in t:
                return intent
    return "general"


def basic_normalize(question: str) -> str:
    q = (question or "").strip().lower()
    q = re.sub(r"[^\w\s]", " ", q)
    q = re.sub(r"\s+", " ", q).strip()
    return q


def canonical_key(question: str) -> str:
    """
    Deterministic meaning key:
      intent|channel|state|month
    Any missing becomes "any".
    """
    q = question or ""
    intent = detect_intent(q) or "general"
    channel = detect_channel(q) or "any"
    state = extract_state(q) or "any"
    month = extract_month(q) or "any"
    return f"{intent}|{channel}|{state}|{month}"
