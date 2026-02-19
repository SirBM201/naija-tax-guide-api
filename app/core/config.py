# app/core/config.py
import os

def env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()

def env_bool(name: str, default: str = "0") -> bool:
    v = env(name, default).lower()
    return v in ("1", "true", "yes", "y", "on")

def env_int(name: str, default: str = "0") -> int:
    try:
        return int(env(name, default) or default)
    except Exception:
        return int(default)

# ------------------------------------------------------------
# Core
# ------------------------------------------------------------
ENV = env("ENV", "prod")
PORT = int(env("PORT", "8000") or "8000")

# ------------------------------------------------------------
# Routing
# ""  -> routes at /
# "/api" -> routes at /api
# ------------------------------------------------------------
API_PREFIX = env("API_PREFIX", "")  # e.g. "/api"
if API_PREFIX and not API_PREFIX.startswith("/"):
    API_PREFIX = "/" + API_PREFIX
API_PREFIX = API_PREFIX.rstrip("/")  # normalize

# ------------------------------------------------------------
# CORS
# ------------------------------------------------------------
CORS_ORIGINS = env("CORS_ORIGINS", "*")  # comma-separated or "*"

# ------------------------------------------------------------
# Supabase
# ------------------------------------------------------------
SUPABASE_URL = env("SUPABASE_URL")
SUPABASE_ANON_KEY = env("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_ROLE_KEY = env("SUPABASE_SERVICE_ROLE_KEY")

# ------------------------------------------------------------
# Admin / internal auth
# ------------------------------------------------------------
ADMIN_KEY = env("ADMIN_KEY", env("INTERNAL_ADMIN_KEY", ""))

# ------------------------------------------------------------
# Web auth/session (FIX for your ImportError)
# These are imported by: app/core/auth.py
# ------------------------------------------------------------
WEB_AUTH_ENABLED = env_bool("WEB_AUTH_ENABLED", "1")

# Pepper used when hashing/storing web tokens (keep secret in prod)
WEB_TOKEN_PEPPER = env("WEB_TOKEN_PEPPER", "dev_web_token_pepper_change_me")

# Table where web tokens/sessions are stored (if your auth layer uses DB tokens)
WEB_TOKEN_TABLE = env("WEB_TOKEN_TABLE", "web_tokens")

# Optional: session/OTP knobs some modules may reference
WEB_SESSION_TTL_DAYS = env_int("WEB_SESSION_TTL_DAYS", "30")
WEB_OTP_TTL_MINUTES = env_int("WEB_OTP_TTL_MINUTES", "10")

# ------------------------------------------------------------
# OpenAI (if used elsewhere)
# ------------------------------------------------------------
OPENAI_API_KEY = env("OPENAI_API_KEY", env("OPENAI_KEY", ""))

# ------------------------------------------------------------
# Paystack (if used elsewhere)
# ------------------------------------------------------------
PAYSTACK_SECRET_KEY = env("PAYSTACK_SECRET_KEY")
PAYSTACK_PUBLIC_KEY = env("PAYSTACK_PUBLIC_KEY")
PAYSTACK_WEBHOOK_SECRET = env("PAYSTACK_WEBHOOK_SECRET")

# ------------------------------------------------------------
# Misc
# ------------------------------------------------------------
LOG_LEVEL = env("LOG_LEVEL", "INFO")
