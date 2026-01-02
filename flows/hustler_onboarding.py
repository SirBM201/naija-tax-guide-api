def handle_hustler_onboarding(session, message_text):
    step = session["current_step"]
    ctx = session["context"]

    if step == "ASK_BUSINESS_TYPE":
        return {
            "reply": (
                "Welcome 👋\n"
                "What type of hustle do you run?\n"
                "1️⃣ Trading\n2️⃣ Services\n3️⃣ Freelancing\n4️⃣ Other"
            ),
            "next_step": "ASK_LOCATION"
        }

    if step == "ASK_LOCATION":
        ctx["business_type"] = message_text
        return {
            "reply": "Which state are you operating from?",
            "next_step": "ASK_MONTHLY_REVENUE",
            "context": ctx
        }

    if step == "ASK_MONTHLY_REVENUE":
        ctx["location"] = message_text
        return {
            "reply": "Approximate monthly revenue (₦)?",
            "next_step": "COMPLETE",
            "context": ctx
        }

    if step == "COMPLETE":
        ctx["monthly_revenue"] = message_text
        return {
            "reply": (
                "✅ Onboarding complete.\n"
                "You can now ask about:\n"
                "• PAYE tax\n• VAT\n• Business obligations"
            ),
            "end_flow": True,
            "context": ctx
        }
