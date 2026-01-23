# app/services/answers.py
def format_markdown_answer(question: str, answer: str) -> str:
    q = (question or "").strip()
    a = (answer or "").strip()
    if not a:
        a = "No answer available."
    return f"**Q:** {q}\n\n**A:** {a}"
