# app/core/config.py
from __future__ import annotations

import os


def env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or "").strip()


def env_bool(name: str, default: bool = False) -> bool:
    v = env(name, "1" if default else "0").lower()
    return v in ("1", "true", "yes", "y", "on")


# -----------------------------
# Core
# -----------------------------
ENV = env("ENV", "prod")
PORT = int(env("PORT", "8000") or "8000")

# Routing
API_PREFIX = env("API_PREFIX", "")  # "" or "/api"
if API_PREFIX and not API_PREFIX.startswith("/"):
    API_PREFIX = "/" + API_PREFIX
API_PREFIX = API_PREFIX.rstrip("/")

# CORS
CORS_ORIGINS = env("CORS_ORIGINS", "*")  # comma-separated or "*"


# -----------------------------
# Supabase
# -----------------------------
SUPABASE_URL = env("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = env("SUPABASE_SERVICE_ROLE_KEY")


# -----------------------------
# AI / OpenAI
# -----------------------------
OPENAI_API_KEY = env("OPENAI_API_KEY")
OPENAI_MODEL = env("OPENAI_MODEL", "gpt-4o-mini")


# -----------------------------
# Admin API protection
# -----------------------------
ADMIN_API_KEY = env("ADMIN_API_KEY", "")


# -----------------------------
# Web Auth / Web Sessions
# -----------------------------
WEB_AUTH_ENABLED = env_bool("WEB_AUTH_ENABLED", True)

# Session token hashing pepper
WEB_TOKEN_PEPPER = env("WEB_TOKEN_PEPPER", "dev-pepper-change-me")

# OTP hashing pepper (can be same as token pepper, but can be separate)
WEB_OTP_PEPPER = env("WEB_OTP_PEPPER", WEB_TOKEN_PEPPER)

# IMPORTANT: match your actual Supabase tables
# Your updated routes/services assume "web_sessions" (not "web_tokens").
WEB_TOKEN_TABLE = env("WEB_TOKEN_TABLE", "web_sessions")
WEB_OTP_TABLE = env("WEB_OTP_TABLE", "web_otps")

# OTP lifetime
# Keep both seconds + minutes for compatibility with older code paths.
WEB_OTP_TTL_SECONDS = int(env("WEB_OTP_TTL_SECONDS", "600") or "600")  # 10 mins
WEB_OTP_TTL_MINUTES = int(env("WEB_OTP_TTL_MINUTES", str(max(1, WEB_OTP_TTL_SECONDS // 60))) or "10")
WEB_OTP_MAX_ATTEMPTS = int(env("WEB_OTP_MAX_ATTEMPTS", "5") or "5")

# Session lifetime
WEB_SESSION_TTL_DAYS = int(env("WEB_SESSION_TTL_DAYS", "30") or "30")

# Cookie settings (used by web_auth.py; defined here so env naming stays consistent)
WEB_AUTH_COOKIE_NAME = env("WEB_AUTH_COOKIE_NAME", "ntg_session")
WEB_AUTH_COOKIE_SECURE = env_bool("WEB_AUTH_COOKIE_SECURE", True)
WEB_AUTH_COOKIE_SAMESITE = env("WEB_AUTH_COOKIE_SAMESITE", "None")  # "None" for cross-site (Vercel -> Koyeb)
WEB_AUTH_COOKIE_DOMAIN = env("WEB_AUTH_COOKIE_DOMAIN", "")  # usually blank/None unless you know you need it

# Debug
WEB_AUTH_DEBUG = env_bool("WEB_AUTH_DEBUG", False)
WEB_DEV_RETURN_OTP = env_bool("WEB_DEV_RETURN_OTP", False) or (ENV.lower() == "dev")


# -----------------------------
# Paystack
# -----------------------------
PAYSTACK_SECRET_KEY = env("PAYSTACK_SECRET_KEY", "")
PAYSTACK_PUBLIC_KEY = env("PAYSTACK_PUBLIC_KEY", "")
PAYSTACK_CURRENCY = env("PAYSTACK_CURRENCY", "NGN") or "NGN"
PAYSTACK_CALLBACK_URL = env("PAYSTACK_CALLBACK_URL", "")
PAYSTACK_WEBHOOK_TOLERANCE_SECONDS = int(env("PAYSTACK_WEBHOOK_TOLERANCE_SECONDS", "300") or "300")
