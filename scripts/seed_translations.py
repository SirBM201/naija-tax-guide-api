import os
from app.core.supabase_client import supabase
from app.services.openai_client import translate_text  # you implement once

TARGETS = [
    ("answer_yoruba", "yo"),
    ("answer_igbo", "ig"),
    ("answer_hausa", "ha"),
    ("answer_pidgin", "pcm"),
]

BATCH = int(os.getenv("SEED_BATCH", "50"))

def run():
    db = supabase()
    # pull only rows missing any target translation
    rows = (
        db.table("qa_library")
        .select("id, answer_en, answer_yoruba, answer_igbo, answer_hausa, answer_pidgin")
        .eq("enabled", True)
        .not_.is_("answer_en", "null")
        .limit(BATCH)
        .execute()
        .data
        or []
    )

    for r in rows:
        base = (r.get("answer_en") or "").strip()
        if not base:
            continue

        updates = {}
        for col, lang in TARGETS:
            if (r.get(col) or "").strip():
                continue
            updates[col] = translate_text(base, target_lang=lang)  # one call per missing lang

        if updates:
            db.table("qa_library").update(updates).eq("id", r["id"]).execute()

if __name__ == "__main__":
    run()
