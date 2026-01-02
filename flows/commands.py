def handle_command(command: str):
    cmd = command.lower().strip()

    if cmd in ["menu", "help"]:
        return {
            "reply": (
                "📌 *Naija Hustle Tax Guide*\n\n"
                "Reply with:\n"
                "• PAYE – Salary tax\n"
                "• VAT – Business VAT\n"
                "• BUSINESS – Hustler onboarding\n\n"
                "Other commands:\n"
                "• restart – start over\n"
                "• cancel – end session"
            ),
            "end_flow": False
        }

    if cmd == "restart":
        return {"action": "restart"}

    if cmd == "cancel":
        return {"action": "cancel"}

    return None
