# app/core/config.py
from __future__ import annotations

import os


def env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or "").strip()


def env_bool(name: str, default: bool = False) -> bool:
    v = env(name, "1" if default else "0").lower()
    return v in ("1", "true", "yes", "y", "on")


def env_int(name: str, default: int) -> int:
    try:
        return int(env(name, str(default)) or str(default))
    except Exception:
        return default


# -----------------------------
# Core
# -----------------------------
ENV = env("ENV", "prod")
PORT = env_int("PORT", 8000)

# Routing
# ""  -> routes at /
# "/api" -> routes at /api
API_PREFIX = env("API_PREFIX", "")  # e.g. "" or "/api"
if API_PREFIX and not API_PREFIX.startswith("/"):
    API_PREFIX = "/" + API_PREFIX
API_PREFIX = API_PREFIX.rstrip("/")  # normalize

# CORS
CORS_ORIGINS = env("CORS_ORIGINS", "*")  # comma-separated or "*"


# -----------------------------
# Supabase
# -----------------------------
SUPABASE_URL = env("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = env("SUPABASE_SERVICE_ROLE_KEY")


# -----------------------------
# AI / OpenAI (optional)
# -----------------------------
OPENAI_API_KEY = env("OPENAI_API_KEY")
OPENAI_MODEL = env("OPENAI_MODEL", "gpt-4o-mini")


# -----------------------------
# Admin API protection
# -----------------------------
# Used by app/core/security.py via require_admin_key
ADMIN_API_KEY = env("ADMIN_API_KEY", "")


# -----------------------------
# Web Auth / Web Sessions
# -----------------------------
WEB_AUTH_ENABLED = env_bool("WEB_AUTH_ENABLED", True)

# MUST be set in prod (use Koyeb env var). Default only for local/dev.
WEB_TOKEN_PEPPER = env("WEB_TOKEN_PEPPER", "dev-pepper-change-me")

# Tables (match your Supabase)
WEB_TOKEN_TABLE = env("WEB_TOKEN_TABLE", "web_sessions")
WEB_OTP_TABLE = env("WEB_OTP_TABLE", "account_otps")

# OTP options
WEB_OTP_TTL_SECONDS = env_int("WEB_OTP_TTL_SECONDS", 300)   # 5 min
WEB_OTP_MAX_ATTEMPTS = env_int("WEB_OTP_MAX_ATTEMPTS", 5)


# -----------------------------
# Compatibility / future keys
# (Add new config names here FIRST before importing them elsewhere)
# -----------------------------
# Example placeholders (safe defaults):
WEB_AUTH_REQUIRED = env_bool("WEB_AUTH_REQUIRED", False)
