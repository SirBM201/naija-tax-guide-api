# app/core/config.py
import os

def _getenv(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or "").strip()

def _getbool(name: str, default: bool = False) -> bool:
    v = _getenv(name, "true" if default else "false").lower()
    return v in ("1", "true", "yes", "y", "on")

# -----------------------------
# Core / URLs
# -----------------------------
APP_BASE_URL = _getenv("APP_BASE_URL")  # e.g. https://xxxxx.koyeb.app (no trailing slash)

# -----------------------------
# Supabase
# -----------------------------
SUPABASE_URL = _getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = _getenv("SUPABASE_SERVICE_ROLE_KEY")

# -----------------------------
# Telegram
# -----------------------------
TELEGRAM_BOT_TOKEN = _getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_WEBHOOK_URL = _getenv("TELEGRAM_WEBHOOK_URL")  # should be: https://xxxxx.koyeb.app/telegram/webhook
TELEGRAM_WEBHOOK_SECRET = _getenv("TELEGRAM_WEBHOOK_SECRET")  # secret token header
TELEGRAM_SHORT_MODE = _getbool("TELEGRAM_SHORT_MODE", False)

# -----------------------------
# CORS
# -----------------------------
# Comma-separated list of allowed origins, or "*" for all.
CORS_ORIGINS = _getenv("CORS_ORIGINS", "*")

allowed_origins = [o.strip() for o in CORS_ORIGINS.split(",") if o.strip()] if CORS_ORIGINS else ["*"]
if not allowed_origins:
    allowed_origins = ["*"]
