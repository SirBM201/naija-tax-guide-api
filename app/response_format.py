import re

DISCLAIMER = (
  "_Disclaimer: This is general guidance. For binding advice, confirm with FIRS / your State IRS "
  "or a qualified tax professional._"
)

def format_markdown_answer(question: str, raw_answer: str) -> str:
    # Clean up spacing
    a = (raw_answer or "").strip()
    a = re.sub(r"\n{3,}", "\n\n", a)

    # If answer is empty, return a safe fallback
    if not a:
        return (
            "### Direct Answer\n"
            "I couldn’t generate a reliable answer for that question.\n\n"
            "### What I need from you\n"
            "- Your state of operation\n"
            "- Individual or business?\n"
            "- What type of income/transaction?\n\n"
            f"{DISCLAIMER}"
        )

    return (
        "### Direct Answer\n"
        f"{a}\n\n"
        "### What to do next\n"
        "- Confirm whether this applies to your **state** and your **business type**.\n"
        "- Keep supporting documents (invoices/receipts, bank statements, contracts).\n"
        "- If you’re unsure, verify with **FIRS / State IRS** before filing.\n\n"
        "### Documents to keep\n"
        "- Invoices/receipts\n"
        "- Bank statements\n"
        "- Contracts / engagement letters\n"
        "- Payment evidence / schedules\n\n"
        f"{DISCLAIMER}"
    )
