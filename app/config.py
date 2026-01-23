# app/config.py
import os

def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    v = raw.strip().lower()
    if v in ("1", "true", "t", "yes", "y", "on"):
        return True
    if v in ("0", "false", "f", "no", "n", "off", ""):
        return False
    return default

# --- CORS ---
CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:3000").strip()
allowed_origins = [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]

# --- Core ENV (keep here if you want central config later) ---
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY).strip()
PAYSTACK_CALLBACK_URL = os.getenv("PAYSTACK_CALLBACK_URL", "").strip()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()

PRICING_PATH = os.getenv("PRICING_PATH", "/pricing").strip()

# Feature toggles
ENABLE_QA_CACHE = _env_bool("ENABLE_QA_CACHE", True)
ENABLE_QA_LIBRARY = _env_bool("ENABLE_QA_LIBRARY", True)
ENABLE_TYPO_TOLERANT = _env_bool("ENABLE_TYPO_TOLERANT", True)

RPC_MIN_SIM = float(os.getenv("RPC_MIN_SIM", "0.55"))
SIMILARITY_MIN = float(os.getenv("SIMILARITY_MIN", "0.25"))

FREE_DAILY_TOTAL_LIMIT = int(os.getenv("FREE_DAILY_TOTAL_LIMIT", "30").strip())
PAID_DAILY_TOTAL_LIMIT = int(os.getenv("PAID_DAILY_TOTAL_LIMIT", "2000").strip())
