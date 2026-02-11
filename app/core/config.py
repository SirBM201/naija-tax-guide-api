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

# Response refinement (shared across cache + AI + all channels)
# REFINE_ENABLED=1
# ADD_TAX_DISCLAIMER=1
# ANSWER_MAX_CHARS=6000
