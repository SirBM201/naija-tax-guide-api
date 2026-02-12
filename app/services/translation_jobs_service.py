# app/services/translation_jobs_service.py
from __future__ import annotations
from typing import Optional
from ..core.supabase_client import supabase
from .lang_service import normalize_lang


def enqueue_missing_translations(*, canonical_key: str, target_lang: str, source_lang: str = "en", source_table: str = "qa_cache") -> None:
    canonical_key = (canonical_key or "").strip()
    target_lang = normalize_lang(target_lang)
    source_lang = normalize_lang(source_lang)
    source_table = (source_table or "qa_cache").strip()

    if not canonical_key or not target_lang or target_lang == source_lang:
        return

    # idempotent due to unique index uq_translation_jobs_unique
    payload = {
        "canonical_key": canonical_key,
        "source_lang": source_lang,
        "target_lang": target_lang,
        "source_table": source_table,
        "status": "pending",
    }
    supabase.table("translation_jobs").upsert(payload).execute()
