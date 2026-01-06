import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    APP_PORT = int(os.getenv("APP_PORT", "5000"))
    APP_ENV = os.getenv("APP_ENV", "development")
    BASE_URL = os.getenv("BASE_URL", "")

    SUPABASE_URL = os.getenv("SUPABASE_URL", "")
    SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

    WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
    WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
    WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")

    FREE_DAILY_LIMIT = int(os.getenv("FREE_DAILY_LIMIT", "5"))
    PAID_DAILY_LIMIT = int(os.getenv("PAID_DAILY_LIMIT", "50"))

settings = Settings()
