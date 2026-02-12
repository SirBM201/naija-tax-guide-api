from __future__ import annotations
from typing import Optional
from ..core.supabase_client import supabase

def enqueue_translation_job(*, canonical_key: str, kind: str, target_lang: str, source_table: str, source_lang: str = "en") -> None:
    if not canonical_key or not target_lang:
        return
    payload = {
        "canonical_key": canonical_key,
        "kind": kind,  # 'answer' or 'question'
        "source_lang": source_lang,
        "target_lang": target_lang,
        "source_table": source_table,  # 'qa_library' or 'qa_cache'
        "status": "pending",
    }
    supabase.table("translation_jobs").upsert(
        payload,
        on_conflict="canonical_key,kind,source_lang,target_lang,source_table",
    ).execute()
