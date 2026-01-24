# app/core/config.py
import os
from typing import List

def _getenv(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or "").strip()

# -----------------------------
# Supabase
# -----------------------------
SUPABASE_URL = _getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = _getenv("SUPABASE_SERVICE_ROLE_KEY")

# -----------------------------
# Paystack (keep for later; harmless if unused)
# -----------------------------
PAYSTACK_SECRET_KEY = _getenv("PAYSTACK_SECRET_KEY")
PAYSTACK_WEBHOOK_SECRET = _getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY)

# -----------------------------
# App / CORS
# -----------------------------
APP_BASE_URL = _getenv("APP_BASE_URL")  # e.g. https://xxxx.koyeb.app
ALLOWED_ORIGINS_RAW = _getenv("ALLOWED_ORIGINS", "*")

def _parse_origins(raw: str) -> List[str]:
    raw = (raw or "").strip()
    if not raw or raw == "*":
        return ["*"]
    # comma-separated
    return [o.strip() for o in raw.split(",") if o.strip()]

allowed_origins = _parse_origins(ALLOWED_ORIGINS_RAW)

# -----------------------------
# Telegram
# -----------------------------
TELEGRAM_BOT_TOKEN = _getenv("TELEGRAM_BOT_TOKEN")

# This MUST match the <secret> in your webhook URL path:
# /telegram/webhook/<secret>
TELEGRAM_WEBHOOK_SECRET = _getenv("TELEGRAM_WEBHOOK_SECRET")

# Optional simple admin key if you want protected admin endpoints later
ADMIN_API_KEY = _getenv("ADMIN_API_KEY")
