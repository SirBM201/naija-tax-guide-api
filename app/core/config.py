# app/core/config.py
import os

def env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()

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
WEB_DEV_RETURN_OTP = env("WEB_DEV_RETURN_OTP", "0") in ("1", "true", "yes", "on")

# Optional knobs (safe defaults)
OTP_TTL_SECONDS = int(env("OTP_TTL_SECONDS", "600") or "600")              # 10 mins
OTP_COOLDOWN_SECONDS = int(env("OTP_COOLDOWN_SECONDS", "60") or "60")      # 1 min
WEB_SESSION_TTL_SECONDS = int(env("WEB_SESSION_TTL_SECONDS", "2592000") or "2592000")  # 30 days
