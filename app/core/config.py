# app/core/config.py
import os
from typing import Dict, List


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    v = raw.strip().lower()
    if v in ("1", "true", "t", "yes", "y", "on"):
        return True
    if v in ("0", "false", "f", "no", "n", "off", ""):
        return False
    return default


# Supabase
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

# App base URL (used for callback fallbacks)
APP_BASE_URL = os.getenv("APP_BASE_URL", "").strip()

# Paystack
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY).strip()
PAYSTACK_CALLBACK_URL = os.getenv("PAYSTACK_CALLBACK_URL", "").strip()

# OpenAI
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()
OPENAI_TTS_MODEL = os.getenv("OPENAI_TTS_MODEL", "gpt-4o-mini-tts").strip()
OPENAI_TTS_VOICE = os.getenv("OPENAI_TTS_VOICE", "alloy").strip()

# Storage (optional; safe if unused)
VOICE_BUCKET = os.getenv("VOICE_BUCKET", "voice-cache").strip()
SUPABASE_STORAGE_URL = os.getenv("SUPABASE_STORAGE_URL", "").strip()
VOICE_PUBLIC_BASE = os.getenv("VOICE_PUBLIC_BASE", "").strip()

# Usage limits
FREE_DAILY_TOTAL_LIMIT = int(os.getenv("FREE_DAILY_TOTAL_LIMIT", "30").strip())
PAID_DAILY_TOTAL_LIMIT = int(os.getenv("PAID_DAILY_TOTAL_LIMIT", "2000").strip())

# Feature toggles
ENABLE_QA_CACHE = _env_bool("ENABLE_QA_CACHE", True)
ENABLE_QA_LIBRARY = _env_bool("ENABLE_QA_LIBRARY", True)
ENABLE_TYPO_TOLERANT = _env_bool("ENABLE_TYPO_TOLERANT", True)

# RPC typo tolerant search
RPC_MIN_SIM = float(os.getenv("RPC_MIN_SIM", "0.55"))

# Answer columns (multi-language)
ANSWER_COLS = "answer,answer_en,answer_pcm,answer_yo,answer_ig,answer_ha"

# Synonyms (simple keyword expansion)
SYNONYMS: Dict[str, List[str]] = {
    "vat": ["value added tax", "value-added tax"],
    "paye": ["pay as you earn", "pay-as-you-earn"],
    "wht": ["withholding tax", "with-holding tax", "withholding"],
    "tin": ["tax identification number"],
    "firs": ["federal inland revenue service"],
    "jtb": ["joint tax board"],
}

# Credits rules (used by enforcement)
MONTHLY_AI_CREDITS = int(os.getenv("MONTHLY_AI_CREDITS", "300").strip())
VOICE_AI_COST = int(os.getenv("VOICE_AI_COST", "3").strip())
TEXT_AI_COST = int(os.getenv("TEXT_AI_COST", "1").strip())
VOICE_CACHED_FIRST_GEN_COST = int(os.getenv("VOICE_CACHED_FIRST_GEN_COST", "1").strip())

# Pricing path (for messages)
PRICING_PATH = os.getenv("PRICING_PATH", "/pricing").strip() or "/pricing"

# Plans (single source of truth)
PLAN_RULES = {
    "monthly":   {"amount_kobo": 3000 * 100,  "days": 30,  "currency": "NGN"},
    "quarterly": {"amount_kobo": 8000 * 100,  "days": 90,  "currency": "NGN"},
    "yearly":    {"amount_kobo": 30000 * 100, "days": 365, "currency": "NGN"},
}

# Telegram
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()

# CORS
CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:3000").strip()
allowed_origins = [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]
