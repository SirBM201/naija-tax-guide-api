from __future__ import annotations

from typing import Dict, Optional


def compose_tax_payment_process() -> Dict:
    answer = """
To pay tax in Nigeria, follow these steps:

1. Identify the exact tax type involved.
   - Personal Income Tax
   - Company Income Tax
   - VAT
   - Withholding Tax
   - PAYE

2. Confirm the correct tax authority.
   - FIRS usually handles many federal taxes
   - State Internal Revenue Services usually handle Personal Income Tax and PAYE matters for employees in the state

3. Make sure your registration details are in place, especially your TIN.

4. Prepare and file the relevant return if that tax type requires a return before payment.

5. Generate the payment reference through the official portal or approved payment channel.

6. Pay through an approved method such as:
   - official tax portal
   - approved bank channel
   - approved payment platform like Remita where applicable

7. Keep the payment receipt and filing evidence for your records.

If you tell me the exact tax type, I can guide you more precisely.
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

1. Identify whether you are registering as:
   - an individual
   - a business name
   - a company

2. Go through the appropriate tax authority or approved registration channel.

3. Prepare the common details usually required:
   - full name or business name
   - address
   - phone number
   - email where applicable
   - business registration details for a company or registered business

4. Submit the required identification or registration documents.

5. After successful registration, the TIN is issued and linked to your tax profile.

TIN is commonly required for filing returns, paying taxes, and dealing with official tax records.
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


def compose_tax_filing_process() -> Dict:
    answer = """
To file tax in Nigeria, use this general process:

1. Determine the taxpayer type.
   - employee
   - self-employed individual
   - registered business
   - company

2. Confirm the correct tax authority.
   - Personal Income Tax is often handled at state level
   - some federal taxes are handled through FIRS

3. Gather the records needed for the filing period, such as:
   - income records
   - expense records where relevant
   - payroll records where relevant
   - prior payments or credits
   - TIN and registration details

4. Identify the exact return to be filed.

5. Complete the return with the correct figures for the relevant period.

6. Submit the return through the approved channel.

7. Pay any amount due if payment is required.

8. Keep evidence of filing and payment.

If you tell me whether you are filing as an employee, freelancer, business owner, or company, I can narrow the steps further.
""".strip()

    return {
        "answer": answer,
        "meta": {
            "intent_type": "tax_filing_process",
            "answer_mode": "process",
            "source_type": "tax_kb",
            "source_label": "General Tax Filing Process",
            "grounded": True,
        },
    }


def compose_vat_filing_process() -> Dict:
    answer = """
To file VAT in Nigeria, use this general flow:

1. Confirm that VAT applies to your business activity.

2. Gather the records for the filing period:
   - sales subject to VAT
   - VAT charged to customers
   - input VAT where applicable
   - invoices and supporting records

3. Prepare the VAT return for the relevant period.

4. Submit the VAT return through the approved tax filing channel.

5. Pay any VAT due through the approved payment channel.

6. Keep the return confirmation, payment receipt, and supporting records.

If you want, I can also explain VAT in simpler terms or help you understand what records should be prepared before filing.
""".strip()

    return {
        "answer": answer,
        "meta": {
            "intent_type": "vat_filing_process",
            "answer_mode": "process",
            "source_type": "tax_kb",
            "source_label": "VAT Filing Process",
            "grounded": True,
        },
    }


def compose_paye_remittance_process() -> Dict:
    answer = """
To handle PAYE remittance in Nigeria, use this general process:

1. Confirm that you are acting as an employer.

2. Calculate the PAYE to be withheld from employee income for the period.

3. Prepare the employee payroll and deduction schedule.

4. Complete the required PAYE return or remittance schedule for the relevant authority.

5. Pay or remit the PAYE through the approved state tax authority channel.

6. Keep evidence of deduction, remittance, and filing for your records.

7. Make sure staff records and payroll records remain consistent with what was remitted.

If you want, I can explain PAYE step by step for a small business employer.
""".strip()

    return {
        "answer": answer,
        "meta": {
            "intent_type": "paye_remittance_process",
            "answer_mode": "process",
            "source_type": "tax_kb",
            "source_label": "PAYE Remittance Process",
            "grounded": True,
        },
    }


PROCESS_MAP = {
    "tax_payment_process": compose_tax_payment_process,
    "tin_registration": compose_tin_registration,
    "tax_filing_process": compose_tax_filing_process,
    "vat_filing_process": compose_vat_filing_process,
    "paye_remittance_process": compose_paye_remittance_process,
}


def try_compose(intent: Optional[str]):
    if not intent:
        return None

    fn = PROCESS_MAP.get(str(intent).strip())
    if not fn:
        return None

    return fn()
