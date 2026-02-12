# scripts/translation_seeder.py
from __future__ import annotations
import os
import time
from typing import Optional, Dict, Any, List

from app.core.supabase_client import supabase

# If you're using OpenAI SDK in your project already, keep consistent with that.
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

MODEL = os.getenv("OPENAI_TRANSLATE_MODEL", "gpt-4o-mini")  # cheap + good

LANG_NAME = {"yo": "Yoruba", "ig": "Igbo", "ha": "Hausa", "pcm": "Nigerian Pidgin", "en": "English"}

def translate_text(text: str, target_lang: str) -> str:
    tgt = LANG_NAME.get(target_lang, target_lang)
    prompt = (
        f"Translate the following text into {tgt}.\n"
        f"Keep formatting clean and professional.\n"
        f"- Preserve bullet points\n"
        f"- Preserve bold emphasis if present\n"
        f"- Do NOT add new advice\n\n"
        f"TEXT:\n{text}"
    )

    resp = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": "You are a precise professional translator."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.0,
    )
    out = (resp.choices[0].message.content or "").strip()
    return out

def fetch_pending_jobs(limit: int = 25) -> List[Dict[str, Any]]:
    r = (
        supabase.table("translation_jobs")
        .select("id, canonical_key, target_lang, source_table, attempts")
        .eq("status", "pending")
        .order("created_at", desc=False)
        .limit(limit)
        .execute()
    )
    return r.data or []

def mark_job(job_id: str, status: str, error: Optional[str] = None, attempts: int = 0) -> None:
    supabase.table("translation_jobs").update(
        {"status": status, "error": error, "attempts": attempts, "updated_at": "now()"}
    ).eq("id", job_id).execute()

def update_library_translation(canonical_key: str, target_lang: str, translated: str) -> None:
    col_map = {
        "yo": "answer_yoruba",
        "ig": "answer_igbo",
        "ha": "answer_hausa",
        "pcm": "answer_pidgin",
    }
    col = col_map.get(target_lang)
    if not col:
        return

    supabase.table("qa_library").update({col: translated}).eq("canonical_key", canonical_key).execute()

def run_batch() -> int:
    jobs = fetch_pending_jobs(limit=25)
    if not jobs:
        return 0

    for j in jobs:
        jid = j["id"]
        ck = j["canonical_key"]
        tgt = j["target_lang"]
        attempts = int(j.get("attempts") or 0) + 1

        try:
            # Pull source English from qa_library
            src = (
                supabase.table("qa_library")
                .select("answer_en, enabled")
                .eq("canonical_key", ck)
                .eq("enabled", True)
                .limit(1)
                .execute()
            ).data or []

            if not src:
                mark_job(jid, "failed", error="source_not_found", attempts=attempts)
                continue

            answer_en = (src[0].get("answer_en") or "").strip()
            if not answer_en:
                mark_job(jid, "failed", error="source_empty", attempts=attempts)
                continue

            translated = translate_text(answer_en, tgt)
            translated = (translated or "").strip()
            if not translated:
                mark_job(jid, "failed", error="translation_empty", attempts=attempts)
                continue

            update_library_translation(ck, tgt, translated)
            mark_job(jid, "done", error=None, attempts=attempts)

            time.sleep(0.2)  # gentle pacing

        except Exception as e:
            # fail-safe retries
            if attempts >= 3:
                mark_job(jid, "failed", error=str(e)[:300], attempts=attempts)
            else:
                # keep pending for retry
                mark_job(jid, "pending", error=str(e)[:300], attempts=attempts)

    return len(jobs)

if __name__ == "__main__":
    total = 0
    for _ in range(10):  # up to 250 jobs per run
        n = run_batch()
        total += n
        if n == 0:
            break
    print(f"translation_seeder done: processed={total}")
