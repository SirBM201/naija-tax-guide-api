# tools/translate_seeder.py
from __future__ import annotations
import os
import sys
import json
import time
from typing import List, Dict, Any, Optional, Tuple

import requests

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini").strip()

BATCH_LIMIT = int(os.getenv("SEED_BATCH_LIMIT", "25"))

TARGET_LANGS = ["pcm", "yo", "ig", "ha"]

# Map to your qa_library columns (supports both styles; pick one standard)
LANG_TO_COL = {
    "pcm": "answer_pcm",
    "yo": "answer_yo",
    "ig": "answer_ig",
    "ha": "answer_ha",
}

def _sb_headers() -> Dict[str, str]:
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }

def _sb_get(path: str, params: Dict[str, str]) -> Any:
    url = f"{SUPABASE_URL}/rest/v1/{path}"
    r = requests.get(url, headers=_sb_headers(), params=params, timeout=60)
    r.raise_for_status()
    return r.json()

def _sb_patch(path: str, params: Dict[str, str], payload: Dict[str, Any]) -> Any:
    url = f"{SUPABASE_URL}/rest/v1/{path}"
    headers = _sb_headers()
    headers["Prefer"] = "return=representation"
    r = requests.patch(url, headers=headers, params=params, data=json.dumps(payload), timeout=60)
    r.raise_for_status()
    return r.json()

def _openai_translate(text: str, target_lang: str) -> str:
    """
    Uses OpenAI Responses API.
    Keeps formatting, bullets, bold where applicable.
    """
    if not OPENAI_API_KEY:
        raise RuntimeError("OPENAI_API_KEY missing")

    lang_name = {"pcm": "Nigerian Pidgin", "yo": "Yorùbá", "ig": "Igbo", "ha": "Hausa"}.get(target_lang, target_lang)

    system = (
        "You are a professional tax support translator for Nigerian audiences. "
        "Translate the user-facing answer accurately into the requested language. "
        "Rules:\n"
        "- Keep the meaning exact.\n"
        "- Keep lists, bullets, and numbering.\n"
        "- Keep any **bold** markers as-is.\n"
        "- Do not add extra commentary.\n"
        "- Output only the translated text.\n"
    )

    user = f"Translate to {lang_name}:\n\n{text}"

    url = "https://api.openai.com/v1/responses"
    payload = {
        "model": OPENAI_MODEL,
        "input": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.2,
    }

    r = requests.post(
        url,
        headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
        data=json.dumps(payload),
        timeout=120,
    )
    r.raise_for_status()
    data = r.json()

    # Responses API output extraction (robust)
    out_text = ""
    try:
        for item in data.get("output", []):
            for c in item.get("content", []):
                if c.get("type") == "output_text":
                    out_text += c.get("text", "")
    except Exception:
        pass

    return (out_text or "").strip()

def _needs_translation(row: Dict[str, Any], col: str) -> bool:
    v = row.get(col)
    return not (isinstance(v, str) and v.strip())

def main() -> int:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        print("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY", file=sys.stderr)
        return 2

    # Pull rows that have answer_en but are missing at least one target lang column
    # NOTE: Supabase REST filter syntax: col=is.null / col=not.is.null
    # We'll fetch a batch and decide in code (simpler + robust).
    rows = _sb_get(
        "qa_library",
        params={
            "select": "id,canonical_key,enabled,answer_en,answer_pcm,answer_yo,answer_ig,answer_ha,updated_at",
            "enabled": "eq.true",
            "answer_en": "not.is.null",
            "limit": str(BATCH_LIMIT),
            "order": "updated_at.asc",
        },
    )

    if not rows:
        print("No rows found.")
        return 0

    translated = 0

    for row in rows:
        base = (row.get("answer_en") or "").strip()
        if not base:
            continue

        update: Dict[str, Any] = {}

        for lang in TARGET_LANGS:
            col = LANG_TO_COL[lang]
            if _needs_translation(row, col):
                try:
                    t = _openai_translate(base, lang)
                    if t:
                        update[col] = t
                        time.sleep(0.2)  # light throttle
                except Exception as e:
                    print(f"Translate failed for id={row.get('id')} lang={lang}: {e}", file=sys.stderr)

        if update:
            # patch by id
            _sb_patch("qa_library", params={"id": f"eq.{row['id']}"}, payload=update)
            translated += 1

    print(f"Done. Updated rows: {translated}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
