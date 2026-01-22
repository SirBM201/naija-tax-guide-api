# === FIXED HELPERS FOR Naija Tax Guide ===
# Drop-in helpers to prevent NameError / TypeError crashes
# Paste this at the TOP of app/main.py (or merge into your file)

# --- Synonyms used by expand_queries ---
SYNONYMS = {
    "wht": ["withholding tax", "with holding tax", "withholding"],
    "vat": ["value added tax"],
    "paye": ["pay as you earn", "payee"],
    "tin": ["tax identification number"],
}

# --- Columns selector for qa_library ---
ANSWER_COLS = "answer,answer_en,answer_pcm,answer_yo,answer_ig,answer_ha"

# --- Pick best localized answer safely ---
def pick_answer(row: dict, lang: str) -> str:
    if not isinstance(row, dict):
        return ""
    if lang == "yo":
        return row.get("answer_yo") or row.get("answer_en") or row.get("answer") or ""
    if lang == "ig":
        return row.get("answer_ig") or row.get("answer_en") or row.get("answer") or ""
    if lang == "ha":
        return row.get("answer_ha") or row.get("answer_en") or row.get("answer") or ""
    if lang == "pcm":
        return row.get("answer_pcm") or row.get("answer_en") or row.get("answer") or ""
    return row.get("answer_en") or row.get("answer") or ""

# --- Make can_use_ai signature backward-compatible ---
def can_use_ai(wa_phone, credits_needed=1):
    # Default allow AI if wallet/limits are not enforced yet
    return True, None, None
