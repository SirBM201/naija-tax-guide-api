# app/services/answers.py
def format_markdown_answer(question: str, answer: str) -> str:
    q = (question or "").strip()
    a = (answer or "").strip()
    if not a:
        a = "Sorry, I don't have an answer for that yet."
    return f"*Question:* {q}\n\n*Answer:* {a}"
