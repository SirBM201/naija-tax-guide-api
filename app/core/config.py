import os

def _get(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or "").strip()

# -----------------------------
# Core
# -----------------------------
SUPABASE_URL = _get("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = _get("SUPABASE_SERVICE_ROLE_KEY")

ADMIN_API_KEY = _get("ADMIN_API_KEY")

APP_BASE_URL = _get("APP_BASE_URL")  # e.g. https://xxxxx.koyeb.app

# -----------------------------
# Paystack (keep even if unused for now)
# -----------------------------
PAYSTACK_SECRET_KEY = _get("PAYSTACK_SECRET_KEY")
PAYSTACK_WEBHOOK_SECRET = _get("PAYSTACK_WEBHOOK_SECRET") or PAYSTACK_SECRET_KEY

# -----------------------------
# Telegram
# -----------------------------
TELEGRAM_BOT_TOKEN = _get("TELEGRAM_BOT_TOKEN")
TELEGRAM_WEBHOOK_SECRET = _get("TELEGRAM_WEBHOOK_SECRET")  # MUST match the secret in URL path
TELEGRAM_WEBHOOK_URL = _get("TELEGRAM_WEBHOOK_URL")        # full URL you set in Telegram
TELEGRAM_SHORT_MODE = (_get("TELEGRAM_SHORT_MODE", "true").lower() in ("1", "true", "yes", "on"))

# -----------------------------
# CORS
# -----------------------------
# Comma-separated list in env: "https://thecre8hub.com,http://localhost:3000"
_allowed = _get("ALLOWED_ORIGINS", "*")
if _allowed == "*" or _allowed == "":
    allowed_origins = ["*"]
else:
    allowed_origins = [x.strip() for x in _allowed.split(",") if x.strip()]
