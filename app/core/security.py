import os
import time
import hmac
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Tuple

OTP_TTL_MINUTES = int(os.getenv("OTP_TTL_MINUTES", "10"))
OTP_DEV_MODE = os.getenv("OTP_DEV_MODE", "0").strip() == "1"

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def make_otp_code() -> str:
    # 6-digit numeric OTP
    return f"{secrets.randbelow(1_000_000):06d}"

def otp_expires_at() -> datetime:
    return now_utc() + timedelta(minutes=OTP_TTL_MINUTES)

def safe_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a or "", b or "")

class SimpleThrottle:
    """
    In-memory throttle (works fine on single instance).
    If you scale horizontally later, move this to Redis.
    """
    def __init__(self):
        self._store = {}  # key -> [timestamps]

    def allow(self, key: str, max_events: int, window_seconds: int) -> bool:
        t = time.time()
        arr = self._store.get(key, [])
        arr = [x for x in arr if (t - x) <= window_seconds]
        if len(arr) >= max_events:
            self._store[key] = arr
            return False
        arr.append(t)
        self._store[key] = arr
        return True

throttle = SimpleThrottle()
