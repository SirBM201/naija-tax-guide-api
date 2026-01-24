# app/core/config.py
import os

def _env(key: str, default: str = "") -> str:
    return (os.getenv(key, default) or "").strip()

# -----------------------------
# Core / Supabase
# -----------------------------
SUPABASE_URL = _env("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = _env("SUPABASE_SERVICE_ROLE_KEY")

# -----------------------------
# Telegram
# -----------------------------
TELEGRAM_BOT_TOKEN = _env("TELEGRAM_BOT_TOKEN")

# If you use "secret in URL", this should match the <secret> part.
# If you use Telegram's secret_token header, this should match that header value.
TELEGRAM_WEBHOOK_SECRET = _env("TELEGRAM_WEBHOOK_SECRET")

# Optional: where you want webhook to point. Example:
# https://your-koyeb-app.koyeb.app/telegram/webhook/<secret>
TELEGRAM_WEBHOOK_URL = _env("TELEGRAM_WEBHOOK_URL")

# When true, bot replies more compactly (optional feature)
TELEGRAM_SHORT_MODE = _env("TELEGRAM_SHORT_MODE", "false").lower() in ("1", "true", "yes", "y", "on")

# -----------------------------
# App
# -----------------------------
APP_ENV = _env("APP_ENV", "prod")
LOG_LEVEL = _env("LOG_LEVEL", "INFO").upper()
