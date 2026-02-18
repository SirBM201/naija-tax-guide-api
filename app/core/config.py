# app/core/config.py
from __future__ import annotations

import os


def env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


# ------------------------------------------------------------
# Core / App
# ------------------------------------------------------------
ENV = env("ENV", "prod")
PORT = int(env("PORT", "8000") or "8000")

# ✅ Used by app/core/security.py -> require_admin_key
ADMIN_API_KEY = env("ADMIN_API_KEY", "")

# ✅ Used by web auth token signing (app/services/web_auth_tokens.py)
APP_SECRET_KEY = env("APP_SECRET_KEY", "")

# ✅ Access token TTL (seconds). Default: 30 days
ACCESS_TOKEN_TTL_SECONDS = int(env("ACCESS_TOKEN_TTL_SECONDS", "2592000") or "2592000")

# ✅ DEV helper: if "1"/"true"/"yes", web_auth may return OTP in response (for local dev only)
WEB_DEV_RETURN_OTP = env("WEB_DEV_RETURN_OTP", "0").lower() in ("1", "true", "yes", "y", "on")


# ------------------------------------------------------------
# Routing
# ------------------------------------------------------------
# ""      -> routes at /
# "/api"  -> routes at /api
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
SUPABASE_SERVICE_ROLE_KEY = env("SUPABASE_SERVICE_ROLE_KEY")
SUPABASE_ANON_KEY = env("SUPABASE_ANON_KEY", "")


# ------------------------------------------------------------
# OpenAI (if used)
# ------------------------------------------------------------
OPENAI_API_KEY = env("OPENAI_API_KEY", "")
OPENAI_MODEL = env("OPENAI_MODEL", "gpt-4o-mini")


# ------------------------------------------------------------
# Web token hashing (used in app/core/auth.py)
# ------------------------------------------------------------
WEB_TOKEN_PEPPER = env("WEB_TOKEN_PEPPER", "")

WEB_TOKEN_TABLE = env("WEB_TOKEN_TABLE", "web_sessions")
WEB_TOKEN_COL_TOKEN = env("WEB_TOKEN_COL_TOKEN", "token_hash")
WEB_TOKEN_COL_ACCOUNT_ID = env("WEB_TOKEN_COL_ACCOUNT_ID", "account_id")
WEB_TOKEN_COL_EXPIRES_AT = env("WEB_TOKEN_COL_EXPIRES_AT", "expires_at")
WEB_TOKEN_COL_REVOKED_AT = env("WEB_TOKEN_COL_REVOKED_AT", "revoked_at")

# ------------------------------------------------------------
# Optional table names (web portal)
# ------------------------------------------------------------
WEB_OTPS_TABLE = env("WEB_OTPS_TABLE", "web_otps")
WEB_SESSIONS_TABLE = env("WEB_SESSIONS_TABLE", "web_sessions")
WEB_CHAT_SESSIONS_TABLE = env("WEB_CHAT_SESSIONS_TABLE", "web_chat_sessions")
WEB_CHAT_MESSAGES_TABLE = env("WEB_CHAT_MESSAGES_TABLE", "web_chat_messages")
