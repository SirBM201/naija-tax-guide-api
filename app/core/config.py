import os

def env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()

# Core
ENV = env("ENV", "prod")
PORT = int(env("PORT", "8000") or "8000")

# Routing
# ""  -> routes at /
# "/api" -> routes at /api
API_PREFIX = env("API_PREFIX", "")  # e.g. "/api"
if API_PREFIX and not API_PREFIX.startswith("/"):
    API_PREFIX = "/" + API_PREFIX
API_PREFIX = API_PREFIX.rstrip("/")  # normalize

# CORS
CORS_ORIGINS = env("CORS_ORIGINS", "*")  # comma-separated or "*"

# Supabase
SUPABASE_URL = env("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = env("SUPABASE_SERVICE_ROLE_KEY")

# Security
ADMIN_API_KEY = env("ADMIN_API_KEY")  # required for manual activation endpoint

# App behavior
DEFAULT_PLAN_NAME = env("DEFAULT_PLAN_NAME", "Free")  # optional
