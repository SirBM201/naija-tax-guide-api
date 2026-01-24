from typing import Optional, Dict, Any
from app.db.supabase_client import sb  # adapt to your existing supabase client import


def suggestion_put(
    normalized_question: str,
    answer: str,
    lang: str = "en",
    question_raw: Optional[str] = None,
    source: str = "ai",
    engine: str = "openai",
    model: Optional[str] = None,
) -> None:
    sb.table("qa_suggestions").insert({
        "normalized_question": normalized_question,
        "lang": lang,
        "question_raw": question_raw,
        "answer": answer,
        "source": source,
        "engine": engine,
        "model": model,
        "status": "pending",
    }).execute()


def suggestion_latest_pending(normalized_question: str, lang: str = "en") -> Optional[Dict[str, Any]]:
    r = (
        sb.table("qa_suggestions")
        .select("*")
        .eq("normalized_question", normalized_question)
        .eq("lang", lang)
        .eq("status", "pending")
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    data = getattr(r, "data", None) or []
    return data[0] if data else None
