# app/core/config.py
import os

def _csv(value: str) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]

# -----------------------------
# Core
# -----------------------------
ENV = os.getenv("ENV", "production").strip()

# -----------------------------
# CORS
# -----------------------------
ALLOWED_ORIGINS = _csv(os.getenv("ALLOWED_ORIGINS", "*").strip())

def allowed_origins() -> list[str]:
    # Keep as function for backward compatibility with your current imports
    return ALLOWED_ORIGINS

# -----------------------------
# Supabase
# -----------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

# -----------------------------
# Telegram
# -----------------------------
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()
