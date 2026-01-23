# app/services/answers.py
def format_markdown_answer(question: str, answer: str) -> str:
    q = (question or "").strip()
    a = (answer or "").strip()
    if not q:
        return a
    return f"**Q:** {q}\n\n**A:** {a}"
