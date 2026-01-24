# app/core/config.py
import os
from typing import List

def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or "").strip()

# ------------------------------------------------------------
# Core ENV
# ------------------------------------------------------------
ENV = _env("ENV", "prod")  # dev | prod

APP_BASE_URL = _env("APP_BASE_URL")  # e.g. https://xxxxx.koyeb.app

SUPABASE_URL = _env("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = _env("SUPABASE_SERVICE_ROLE_KEY")

# Paystack (if/when you enable)
PAYSTACK_SECRET_KEY = _env("PAYSTACK_SECRET_KEY")
PAYSTACK_WEBHOOK_SECRET = _env("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY)

# WhatsApp (if/when you enable)
WHATSAPP_TOKEN = _env("WHATSAPP_TOKEN")
WHATSAPP_VERIFY_TOKEN = _env("WHATSAPP_VERIFY_TOKEN")
WHATSAPP_PHONE_NUMBER_ID = _env("WHATSAPP_PHONE_NUMBER_ID")
WHATSAPP_BUSINESS_ACCOUNT_ID = _env("WHATSAPP_BUSINESS_ACCOUNT_ID")

# Telegram
TELEGRAM_BOT_TOKEN = _env("TELEGRAM_BOT_TOKEN")
TELEGRAM_WEBHOOK_SECRET = _env("TELEGRAM_WEBHOOK_SECRET")
TELEGRAM_WEBHOOK_URL = _env("TELEGRAM_WEBHOOK_URL")
TELEGRAM_SHORT_MODE = _env("TELEGRAM_SHORT_MODE", "true").lower() in ("1", "true", "yes", "on")

# Admin
ADMIN_API_KEY = _env("ADMIN_API_KEY")

# ------------------------------------------------------------
# CORS
# ------------------------------------------------------------
# app/__init__.py expects allowed_origins to exist.
# Configure via CORS_ALLOWED_ORIGINS:
#   "*"  (not recommended for prod)
#   "https://thecre8hub.com,https://www.thecre8hub.com,http://localhost:3000"
CORS_ALLOWED_ORIGINS = _env("CORS_ALLOWED_ORIGINS", "*")

def _parse_origins(value: str) -> List[str]:
    v = (value or "").strip()
    if not v:
        return ["*"]
    if v == "*":
        return ["*"]
    return [o.strip() for o in v.split(",") if o.strip()]

allowed_origins = _parse_origins(CORS_ALLOWED_ORIGINS)
