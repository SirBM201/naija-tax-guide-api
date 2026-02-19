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
# AI / OpenAI (if you use it)
# -----------------------------
OPENAI_API_KEY = env("OPENAI_API_KEY")
OPENAI_MODEL = env("OPENAI_MODEL", "gpt-4o-mini")  # safe default


# -----------------------------
# Admin API protection
# -----------------------------
# Used by app/core/security.py via require_admin_key
# Set this in Koyeb env vars; leave blank to DISABLE admin enforcement (or enforce anyway in code).
ADMIN_API_KEY = env("ADMIN_API_KEY", "")


# -----------------------------
# Web Auth / Web Sessions
# -----------------------------
# Toggle web auth endpoints / decorators
WEB_AUTH_ENABLED = env_bool("WEB_AUTH_ENABLED", True)

# Used to hash/pepper web session tokens. MUST be set in prod.
WEB_TOKEN_PEPPER = env("WEB_TOKEN_PEPPER", "dev-pepper-change-me")

# Supabase table names (change only if you renamed tables)
WEB_TOKEN_TABLE = env("WEB_TOKEN_TABLE", "web_sessions")
WEB_OTP_TABLE = env("WEB_OTP_TABLE", "account_otps")

# OTP options (used by web_otp_service typically)
WEB_OTP_TTL_SECONDS = int(env("WEB_OTP_TTL_SECONDS", "300") or "300")  # 5 min
WEB_OTP_MAX_ATTEMPTS = int(env("WEB_OTP_MAX_ATTEMPTS", "5") or "5")


# -----------------------------
# Misc / Safety
# -----------------------------
# If you later add more modules, define new config keys HERE first.
