# app/core/config.py
import os


def env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


# Core
ENV = env("ENV", "prod")
PORT = int(env("PORT", "8000") or "8000")

# Routing
API_PREFIX = env("API_PREFIX", "")
if API_PREFIX and not API_PREFIX.startswith("/"):
    API_PREFIX = "/" + API_PREFIX
API_PREFIX = API_PREFIX.rstrip("/")

# CORS
CORS_ORIGINS = env("CORS_ORIGINS", "*")

# Supabase
SUPABASE_URL = env("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = env("SUPABASE_SERVICE_ROLE_KEY")

# Admin
ADMIN_API_KEY = env("ADMIN_API_KEY")

# Plans
DEFAULT_PLAN_NAME = env("DEFAULT_PLAN_NAME", "Free")

# -----------------------------
# Web Auth / Sessions (DEV OTP)
# -----------------------------
# How long OTP is valid (minutes)
WEB_OTP_TTL_MINUTES = int(env("WEB_OTP_TTL_MINUTES", "10") or "10")

# How long web session is valid (days)
WEB_SESSION_TTL_DAYS = int(env("WEB_SESSION_TTL_DAYS", "14") or "14")

# If enabled (1), /web/auth/request-otp returns code_plain in response (DEV ONLY)
WEB_DEV_RETURN_OTP = env("WEB_DEV_RETURN_OTP", "1") in ("1", "true", "TRUE", "yes", "YES")

# Safety: minimum seconds between OTP requests for same contact
WEB_OTP_COOLDOWN_SECONDS = int(env("WEB_OTP_COOLDOWN_SECONDS", "30") or "30")
