PAYE_FLOW_KEY = "paye"

def start():
    return "Welcome to Naija Hustle Tax Guide 🇳🇬\n\nWhat is your monthly income? (₦)"


def handle(state, message, session):
    data = session["data"]

    if state == "ASK_INCOME":
        try:
            income = float(message.replace(",", ""))
            data["monthly_income"] = income
            return {
                "reply": "What state do you work in?",
                "next_state": "ASK_STATE",
                "data": data
            }
        except:
            return {"reply": "Please enter a valid number (₦)", "next_state": state}

    if state == "ASK_STATE":
        data["state"] = message.title()
        return {
            "reply": "Are you a public or private sector worker?",
            "next_state": "ASK_SECTOR",
            "data": data
        }

    if state == "ASK_SECTOR":
        data["sector"] = message.lower()
        return {
            "reply": "Thanks! Calculating your PAYE…",
            "next_state": "DONE",
            "data": data
        }

    return {"reply": "Session completed.", "next_state": "DONE"}
