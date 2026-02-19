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
WEB_TOKEN_PEPPER = env("WEB_TOKEN_PEPPER", "dev-pepper-change-me")
WEB_TOKEN_TABLE = env("WEB_TOKEN_TABLE", "web_sessions")
WEB_OTP_TABLE = env("WEB_OTP_TABLE", "account_otps")
WEB_OTP_TTL_SECONDS = int(env("WEB_OTP_TTL_SECONDS", "300") or "300")
WEB_OTP_MAX_ATTEMPTS = int(env("WEB_OTP_MAX_ATTEMPTS", "5") or "5")


# -----------------------------
# Paystack
# -----------------------------
PAYSTACK_SECRET_KEY = env("PAYSTACK_SECRET_KEY", "")
PAYSTACK_PUBLIC_KEY = env("PAYSTACK_PUBLIC_KEY", "")
PAYSTACK_CURRENCY = env("PAYSTACK_CURRENCY", "NGN") or "NGN"
PAYSTACK_CALLBACK_URL = env("PAYSTACK_CALLBACK_URL", "")
PAYSTACK_WEBHOOK_TOLERANCE_SECONDS = int(env("PAYSTACK_WEBHOOK_TOLERANCE_SECONDS", "300") or "300")
