# app/core/config.py
import os

def env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()

# -----------------------------
# Core
# -----------------------------
ENV = env("ENV", "prod")
PORT = int(env("PORT", "8000") or "8000")

API_PREFIX = env("API_PREFIX", "")
if API_PREFIX and not API_PREFIX.startswith("/"):
    API_PREFIX = "/" + API_PREFIX
API_PREFIX = API_PREFIX.rstrip("/")

CORS_ORIGINS = env("CORS_ORIGINS", "*")

SUPABASE_URL = env("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = env("SUPABASE_SERVICE_ROLE_KEY")

ADMIN_API_KEY = env("ADMIN_API_KEY")

DEFAULT_PLAN_NAME = env("DEFAULT_PLAN_NAME", "Free")

# -----------------------------
# Web Auth / OTP (DEV mode)
# WEB_DEV_RETURN_OTP=1  -> API returns otp in response (dev only)
# -----------------------------
WEB_DEV_RETURN_OTP = env("WEB_DEV_RETURN_OTP", "0").lower() in ("1", "true", "yes", "on")

# -----------------------------
# OTP knobs (COMPATIBILITY)
# web_otp_service.py expects:
#   WEB_OTP_TTL_MINUTES
#   WEB_OTP_COOLDOWN_SECONDS
# -----------------------------
WEB_OTP_TTL_MINUTES = int(env("WEB_OTP_TTL_MINUTES", "10") or "10")              # default 10 mins
WEB_OTP_COOLDOWN_SECONDS = int(env("WEB_OTP_COOLDOWN_SECONDS", "60") or "60")   # default 60s

# Optional seconds-based aliases (for future services)
OTP_TTL_SECONDS = int(env("OTP_TTL_SECONDS", str(WEB_OTP_TTL_MINUTES * 60)) or str(WEB_OTP_TTL_MINUTES * 60))
OTP_COOLDOWN_SECONDS = int(env("OTP_COOLDOWN_SECONDS", str(WEB_OTP_COOLDOWN_SECONDS)) or str(WEB_OTP_COOLDOWN_SECONDS))

# -----------------------------
# Web Session TTL (COMPATIBILITY)
# web_sessions_service.py expects:
#   WEB_SESSION_TTL_DAYS
# -----------------------------
WEB_SESSION_TTL_DAYS = int(env("WEB_SESSION_TTL_DAYS", "30") or "30")  # default 30 days
WEB_SESSION_TTL_SECONDS = int(env("WEB_SESSION_TTL_SECONDS", str(WEB_SESSION_TTL_DAYS * 86400)) or str(WEB_SESSION_TTL_DAYS * 86400))
