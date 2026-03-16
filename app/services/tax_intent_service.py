from __future__ import annotations

import re
from typing import Dict, Optional

PATTERNS = {
    "tin_registration": [
        r"\b(tin|tax identification number)\b",
        r"\b(register|get|obtain|apply for).{0,20}\btin\b",
    ],
    "tax_filing_process": [
        r"\b(how do i|how to|steps to|process for|procedure for).{0,25}\b(file|filing|submit|lodge)\b.{0,20}\b(tax|return|returns)\b",
        r"\b(file|filing|submit|lodge)\b.{0,20}\b(my )?(tax|return|returns)\b",
        r"\bself assessment\b.{0,20}\b(file|filing|submit|return)\b",
    ],
    "vat_filing_process": [
        r"\b(how do i|how to|steps to|process for|procedure for).{0,25}\b(file|submit|remit|pay)\b.{0,20}\bvat\b",
        r"\bvat\b.{0,20}\b(file|submit|remit|payment|return)\b",
    ],
    "paye_remittance_process": [
        r"\b(how do i|how to|steps to|process for|procedure for).{0,25}\b(remit|pay|file|submit)\b.{0,20}\bpaye\b",
        r"\bpaye\b.{0,20}\b(remit|remittance|pay|file|submit)\b",
    ],
    "tax_payment_process": [
        r"\b(how do i|how to|steps to|process for|procedure for).{0,25}\b(pay|payment|remit|remittance)\b.{0,20}\b(tax|taxes)\b",
        r"\bpay tax\b",
        r"\btax payment\b",
        r"\bremita tax\b",
    ],
    "freelancer_tax_obligation": [
        r"\bfreelancer(s)?\b.{0,20}\bpay tax\b",
        r"\bself employed tax nigeria\b",
        r"\bdo freelancers pay tax\b",
    ],
    "record_keeping": [
        r"\bkeep records\b",
        r"\btax records\b",
        r"\baccounting records\b",
        r"\brecord keeping\b",
    ],
    "vat_definition": [
        r"\bwhat is vat\b",
        r"\bdefine vat\b",
    ],
    "vat_rate": [
        r"\bvat rate\b",
        r"\bhow much is vat\b",
        r"\bvat percentage\b",
    ],
    "paye_definition": [
        r"\bwhat is paye\b",
        r"\bdefine paye\b",
    ],
}


def _normalize(text: str) -> str:
    text = str(text or "").strip().lower()
    text = re.sub(r"\s+", " ", text)
    return text


def classify_tax_intent(question: str) -> Optional[str]:
    q = _normalize(question)
    if not q:
        return None

    for intent, patterns in PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, q):
                return intent

    return None


def build_intent_meta(intent: Optional[str]) -> Dict:
    return {
        "intent_type": intent,
        "grounded": bool(intent),
    }
