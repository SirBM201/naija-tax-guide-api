# app/core/config.py
import os
from typing import List


def env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or "").strip()


def env_bool(name: str, default: str = "0") -> bool:
    v = env(name, default).lower()
    return v in ("1", "true", "yes", "y", "on")


def env_int(name: str, default: str) -> int:
    raw = env(name, default)
    try:
        return int(raw)
    except Exception:
        return int(default)


# -----------------------------
# Core
# -----------------------------
ENV = env("ENV", "prod")
PORT = env_int("PORT", "8000")

# Routing
# ""  -> routes at /
# "/api" -> routes at /api
API_PREFIX = env("API_PREFIX", "")
if API_PREFIX and not API_PREFIX.startswith("/"):
    API_PREFIX = "/" + API_PREFIX
API_PREFIX = API_PREFIX.rstrip("/")  # normalize

# CORS
# Comma-separated list OR "*"
CORS_ORIGINS = env("CORS_ORIGINS", "*")
CORS_ORIGINS_LIST: List[str] = (
    ["*"] if CORS_ORIGINS.strip() == "*" else [x.strip() for x in CORS_ORIGINS.split(",") if x.strip()]
)

# Supabase (service role only on backend)
SUPABASE_URL = env("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = env("SUPABASE_SERVICE_ROLE_KEY")

# Admin
ADMIN_API_KEY = env("ADMIN_API_KEY")
DEFAULT_PLAN_NAME = env("DEFAULT_PLAN_NAME", "Free")


# -----------------------------
# Web Auth / OTP (DEV-FIRST)
# -----------------------------
# DEV OTP = cheapest launch option (no SMS/email cost).
# In prod, you can later switch to SMS/Email/WhatsApp OTP providers.
WEB_AUTH_ENABLED = env_bool("WEB_AUTH_ENABLED", "1")

# If enabled, backend will accept a dev OTP pattern (recommended for launch testing).
WEB_AUTH_DEV_OTP_ENABLED = env_bool("WEB_AUTH_DEV_OTP_ENABLED", "1")

# OTP expiry window (seconds)
WEB_AUTH_OTP_TTL_SECONDS = env_int("WEB_AUTH_OTP_TTL_SECONDS", "600")  # 10 min default

# Optional: single master OTP for internal testing (leave empty in real prod)
# Example: WEB_AUTH_MASTER_OTP="123456"
WEB_AUTH_MASTER_OTP = env("WEB_AUTH_MASTER_OTP", "")

# Optional: limit dev OTP usage by domain/app (simple “shared secret”)
# Example: WEB_AUTH_DEV_SHARED_SECRET="mydevsecret"
WEB_AUTH_DEV_SHARED_SECRET = env("WEB_AUTH_DEV_SHARED_SECRET", "")

# Optional: allow only these test phone numbers in dev mode (comma-separated)
# Example: WEB_AUTH_DEV_ALLOWED_PHONES="+2348012345678,+96566182616"
WEB_AUTH_DEV_ALLOWED_PHONES = env("WEB_AUTH_DEV_ALLOWED_PHONES", "")

# If set, only these phones can request/verify OTP in DEV mode.
WEB_AUTH_DEV_ALLOWED_PHONES_LIST: List[str] = (
    [] if not WEB_AUTH_DEV_ALLOWED_PHONES else [x.strip() for x in WEB_AUTH_DEV_ALLOWED_PHONES.split(",") if x.strip()]
)

# Optional pepper for hashing OTPs if you store them (recommended)
OTP_HASH_PEPPER = env("OTP_HASH_PEPPER", "")
