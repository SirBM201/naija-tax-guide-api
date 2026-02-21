from __future__ import annotations

import os


def _env_bool(name: str, default: str = "0") -> bool:
    return (os.getenv(name, default) or default).strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: str) -> int:
    return int((os.getenv(name, default) or default).strip())


class WebAuthConfig:
    # feature flags
    ENABLED: bool = _env_bool("WEB_AUTH_ENABLED", "1")
    DEBUG: bool = _env_bool("WEB_AUTH_DEBUG", "0")

    # cookie
    COOKIE_NAME: str = (os.getenv("WEB_COOKIE_NAME", "ntg_session") or "ntg_session").strip()
    COOKIE_SECURE: bool = _env_bool("COOKIE_SECURE", "1")
    COOKIE_SAMESITE: str = (os.getenv("COOKIE_SAMESITE", "Lax") or "Lax").strip()
    COOKIE_DOMAIN: str | None = (os.getenv("COOKIE_DOMAIN") or "").strip() or None

    # token settings
    TOKEN_TTL_DAYS: int = _env_int("WEB_TOKEN_TTL_DAYS", "30")
    TOKEN_PEPPER: str = (os.getenv("WEB_TOKEN_PEPPER") or "").strip()

    # otp settings
    OTP_TTL_MINUTES: int = _env_int("WEB_OTP_TTL_MINUTES", "10")
    OTP_PEPPER: str = (os.getenv("WEB_OTP_PEPPER") or "").strip()

    # abuse protection
    OTP_MAX_REQUESTS_PER_WINDOW: int = _env_int("WEB_OTP_MAX_REQS", "3")         # per contact/purpose
    OTP_REQUEST_WINDOW_MINUTES: int = _env_int("WEB_OTP_REQ_WINDOW_MIN", "10")
    OTP_MAX_VERIFY_ATTEMPTS: int = _env_int("WEB_OTP_MAX_VERIFY_ATTEMPTS", "5")
    OTP_LOCKOUT_MINUTES: int = _env_int("WEB_OTP_LOCKOUT_MIN", "15")

    @classmethod
    def validate(cls) -> None:
        if not cls.ENABLED:
            return
        if len(cls.TOKEN_PEPPER) < 16:
            raise RuntimeError("WEB_TOKEN_PEPPER is missing or too short (min 16 chars).")
        if len(cls.OTP_PEPPER) < 16:
            raise RuntimeError("WEB_OTP_PEPPER is missing or too short (min 16 chars).")
