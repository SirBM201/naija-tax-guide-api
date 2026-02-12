# scripts/seed_translations_daily.py
from __future__ import annotations

import os
import time
from typing import List, Dict, Any

from openai import OpenAI
from app.core.supabase_client import supabase

# config
BATCH_LIMIT = int(os.getenv("SEED_TRANSLATE_BATCH", "50"))
SLEEP_SEC = float(os.getenv("SEED_TRANSLATE_SLEEP", "0.2"))

TARGETS = [
    ("yo", "answer_yoruba"),
    ("ig", "answer_igbo"),
    ("ha", "answer_hausa"),
    ("pcm", "answer_pidgin"),  # adjust if your column is answer_pcmd
]

def translate_text(client: OpenAI, text_en: str, lang_code: str) -> str:
    prompt = (
        "Translate the text into the requested language.\n"
        "Rules:\n"
        "- Keep it professional and clear.\n"
        "- Preserve bullet points and formatting.\n"
        "- Do NOT add new facts.\n"
        "- Output only the translation.\n\n"
        f"Language: {lang_code}\n\n"
        f"Text:\n{text_en}"
    )
    r = client.responses.create(
        model=os.getenv("OPENAI_TRANSLATE_MODEL", "gpt-4.1-mini"),
        input=prompt,
    )
    out = (r.output_text or "").strip()
    return out

def main() -> None:
    # requires OPENAI_API_KEY and Supabase service env to be available in this job
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    db = supabase()

    # Find rows with answer_en present, enabled true, and at least one missing target column
    # We'll fetch a batch and fill missing columns.
    res = (
        db.table("qa_library")
        .select("id, answer_en, answer_yoruba, answer_igbo, answer_hausa, answer_pidgin, enabled")
        .eq("enabled", True)
        .limit(BATCH_LIMIT)
        .execute()
    )

    rows: List[Dict[str, Any]] = res.data or []
    updated = 0

    for row in rows:
        ans_en = (row.get("answer_en") or "").strip()
        if not ans_en:
            continue

        patch = {}
        for lang_code, col in TARGETS:
            existing = (row.get(col) or "").strip()
            if existing:
                continue
            try:
                patch[col] = translate_text(client, ans_en, lang_code)
                time.sleep(SLEEP_SEC)
            except Exception:
                # skip if translation fails; try again next run
                pass

        if not patch:
            continue

        # mark source/update audit if you want
        patch["updated_at"] = None  # if your table has updated_at, set it properly; else remove this line

        try:
            db.table("qa_library").update(patch).eq("id", row["id"]).execute()
            updated += 1
        except Exception:
            pass

    print({"ok": True, "updated_rows": updated})

if __name__ == "__main__":
    main()
