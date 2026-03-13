# app/services/tax_process_composer.py
from __future__ import annotations

from typing import Dict


def compose_tax_payment_process() -> Dict:
    answer = """
To pay tax in Nigeria, follow these steps:

1. Determine the type of tax you are paying  
   - Personal Income Tax  
   - Value Added Tax (VAT)  
   - Withholding Tax  
   - Company Income Tax  

2. Obtain or confirm your Tax Identification Number (TIN).

3. File the relevant tax return if required.

4. Generate a payment reference through the tax authority system.

5. Pay through an approved channel such as:
   - Remita platform
   - Bank branch
   - Official tax authority portal

6. Keep the payment receipt and filing confirmation.

For federal taxes, payment is usually processed through the Federal Inland Revenue Service (FIRS).  
For personal income tax, payment may be handled by your State Internal Revenue Service.

If you tell me the type of tax you want to pay, I can guide you step-by-step.
""".strip()

    return {
        "answer": answer,
        "meta": {
            "intent_type": "tax_payment_process",
            "answer_mode": "process",
            "source_type": "tax_kb",
            "source_label": "Nigerian Tax Payment Process",
            "grounded": True,
        },
    }


def compose_tin_registration() -> Dict:
    answer = """
To obtain a Tax Identification Number (TIN) in Nigeria:

1. Visit the Federal Inland Revenue Service (FIRS) office or approved registration portal.

2. Provide required details:
   - Name
   - Address
   - Phone number
   - Business information (if applicable)

3. Submit identification documents such as:
   - National ID
   - International passport
   - Business registration documents (for companies)

4. Your TIN will be generated and linked to your tax profile.

TIN is required for most tax filings and payments in Nigeria.
""".strip()

    return {
        "answer": answer,
        "meta": {
            "intent_type": "tin_registration",
            "answer_mode": "process",
            "source_type": "tax_kb",
            "source_label": "TIN Registration Process",
            "grounded": True,
        },
    }


PROCESS_MAP = {
    "tax_payment_process": compose_tax_payment_process,
    "tin_registration": compose_tin_registration,
}


def try_compose(intent: str):
    fn = PROCESS_MAP.get(intent)
    if not fn:
        return None
    return fn()
