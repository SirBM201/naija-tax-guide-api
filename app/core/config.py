import os

def _getenv(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or "").strip()

def _getbool(name: str, default: bool = False) -> bool:
    v = _getenv(name, "true" if default else "false").lower()
    return v in ("1", "true", "yes", "y", "on")

APP_BASE_URL = _getenv("APP_BASE_URL")  # e.g. https://xxxxx.koyeb.app (no trailing slash)

SUPABASE_URL = _getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = _getenv("SUPABASE_SERVICE_ROLE_KEY")

CORS_ORIGINS = _getenv("CORS_ORIGINS", "*")

allowed_origins = [o.strip() for o in CORS_ORIGINS.split(",") if o.strip()] if CORS_ORIGINS else ["*"]
if not allowed_origins:
    allowed_origins = ["*"]
