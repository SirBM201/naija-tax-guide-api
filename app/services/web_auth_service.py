# app/services/web_auth_service.py
from __future__ import annotations

"""
WEB AUTH SERVICE (CANONICAL, FAILURE-EXPOSING)

✅ Canonical identity rule:
    - "account_id" MUST mean: accounts.account_id
    - accounts.id is ONLY the row PK and must never be used as the app identity

Token hashing:
    sha256(f"{WEB_TOKEN_PEPPER}:{raw_token}")
"""

import os
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from app.core.supabase_client import supabase


def _sb():
    return supabase() if callable(supabase) else supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _debug_enabled() -> bool:
    return _truthy(_env("WEB_AUTH_DEBUG", "0")) or _truthy(_env("AUTH_DEBUG", "0"))


def _clip(s: str, n: int = 260) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[:n] + "…"


def _dbg(msg: str) -> None:
    if _debug_enabled():
        print(msg, flush=True)


WEB_AUTH_ENABLED = _truthy(_env("WEB_AUTH_ENABLED", "1"))

WEB_OTPS_TABLE = _env("WEB_OTPS_TABLE", _env("WEB_OTP_TABLE", "web_otps"))
WEB_TOKENS_TABLE = _env("WEB_TOKENS_TABLE", _env("WEB_TOKEN_TABLE", "web_tokens"))
ACCOUNTS_TABLE = _env("ACCOUNTS_TABLE", "accounts")

WEB_AUTH_OTP_TTL_SECONDS = int(_env("WEB_AUTH_OTP_TTL_SECONDS", "600") or "600")
WEB_AUTH_TOKEN_TTL_DAYS = int(_env("WEB_AUTH_TOKEN_TTL_DAYS", _env("WEB_SESSION_TTL_DAYS", "30")) or "30")

WEB_AUTH_COOKIE_NAME = _env("WEB_AUTH_COOKIE_NAME", _env("WEB_COOKIE_NAME", "ntg_session"))

WEB_TOKEN_PEPPER = _env("WEB_TOKEN_PEPPER", _env("ADMIN_API_KEY", "dev-pepper"))
WEB_OTP_PEPPER = _env("WEB_OTP_PEPPER", WEB_TOKEN_PEPPER)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def token_hash(raw_token: str) -> str:
    pepper = (_env("WEB_TOKEN_PEPPER", WEB_TOKEN_PEPPER) or WEB_TOKEN_PEPPER).strip()
    return _sha256_hex(f"{pepper}:{raw_token}")


def otp_hash(contact: str, purpose: str, otp: str) -> str:
    pepper = (_env("WEB_OTP_PEPPER", WEB_OTP_PEPPER) or WEB_OTP_PEPPER).strip()
    return _sha256_hex(f"{pepper}:{contact}:{purpose}:{otp}")


def _has_column(table: str, col: str) -> bool:
    try:
        _sb().table(table).select(col).limit(1).execute()
        return True
    except Exception:
        return False


def _safe_debug_meta() -> Dict[str, Any]:
    if not _debug_enabled():
        return {}
    return {
        "cookie": {"name": WEB_AUTH_COOKIE_NAME},
        "tables": {"otp_table": WEB_OTPS_TABLE, "token_table": WEB_TOKENS_TABLE, "accounts_table": ACCOUNTS_TABLE},
        "env": _env("ENV", "prod").lower(),
    }


def _normalize_bearer(auth_header: str) -> str:
    if not auth_header:
        return ""
    v = auth_header.strip()
    if v.lower().startswith("bearer "):
        return v[7:].strip()
    return ""


def _parse_iso_dt(v: Any) -> Optional[datetime]:
    if not v:
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, str):
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None
    return None


def ensure_web_account_id(contact: str) -> Dict[str, Any]:
    contact = (contact or "").strip().lower()
    if not contact:
        return {"ok": False, "error": "missing_contact", "root_cause": "contact_empty", "fix": "Send non-empty email/contact."}

    if not _has_column(ACCOUNTS_TABLE, "account_id"):
        return {
            "ok": False,
            "error": "schema_invalid",
            "root_cause": f"{ACCOUNTS_TABLE}.account_id column is missing",
            "fix": "Add accounts.account_id (uuid) and use it as the canonical identity everywhere.",
        }

    try:
        q = (
            _sb()
            .table(ACCOUNTS_TABLE)
            .select("id,account_id")
            .eq("provider", "web")
            .eq("provider_user_id", contact)
            .limit(1)
            .execute()
        )
        rows = getattr(q, "data", None) or []
    except Exception as e:
        return {
            "ok": False,
            "error": "accounts_lookup_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check Supabase connectivity/RLS and that accounts table exists.",
            "debug": _safe_debug_meta(),
        }

    if rows:
        row = rows[0] or {}
        row_id = str(row.get("id") or "").strip()
        account_id = str(row.get("account_id") or "").strip()

        if not account_id and row_id:
            try:
                _sb().table(ACCOUNTS_TABLE).update({"account_id": row_id}).eq("id", row_id).execute()
                account_id = row_id
            except Exception as e:
                return {
                    "ok": False,
                    "error": "account_id_repair_failed",
                    "root_cause": f"accounts.account_id is NULL and update failed: {type(e).__name__}: {_clip(str(e))}",
                    "fix": "Run SQL: update accounts set account_id=id where account_id is null; then add UNIQUE index on accounts(account_id). Also ensure RLS allows this update for service role.",
                    "details": {"row_id": row_id, "contact": contact},
                    "debug": _safe_debug_meta(),
                }

        if not account_id:
            return {
                "ok": False,
                "error": "account_id_missing",
                "root_cause": "accounts row exists but account_id is empty",
                "fix": "Ensure accounts.account_id is populated for every row (trigger or migration).",
                "details": {"row": {"id": row_id, "account_id": account_id}},
                "debug": _safe_debug_meta(),
            }

        return {"ok": True, "account_id": account_id, "created": False}

    payload: Dict[str, Any] = {"provider": "web", "provider_user_id": contact}
    if _has_column(ACCOUNTS_TABLE, "display_name"):
        payload["display_name"] = contact

    try:
        ins = _sb().table(ACCOUNTS_TABLE).insert(payload).select("id,account_id").execute()
        data = getattr(ins, "data", None) or []
        row = (data[0] if data else {}) or {}
    except Exception as e:
        return {
            "ok": False,
            "error": "account_create_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check RLS for accounts insert (service role key), and required NOT NULL columns.",
            "details": {"payload_keys": sorted(payload.keys())},
            "debug": _safe_debug_meta(),
        }

    row_id = str(row.get("id") or "").strip()
    account_id = str(row.get("account_id") or "").strip()

    if not account_id and row_id:
        try:
            _sb().table(ACCOUNTS_TABLE).update({"account_id": row_id}).eq("id", row_id).execute()
            account_id = row_id
        except Exception as e:
            return {
                "ok": False,
                "error": "account_id_repair_failed",
                "root_cause": f"created row but failed to set account_id: {type(e).__name__}: {_clip(str(e))}",
                "fix": "Ensure accounts.account_id is writable and RLS allows update for service role.",
                "details": {"row_id": row_id},
                "debug": _safe_debug_meta(),
            }

    if not account_id:
        return {
            "ok": False,
            "error": "account_id_missing",
            "root_cause": "created row but account_id still empty",
            "fix": "Ensure accounts.account_id exists and is populated.",
            "details": {"row_id": row_id},
            "debug": _safe_debug_meta(),
        }

    return {"ok": True, "account_id": account_id, "created": True}


def request_web_otp(
    contact: str,
    purpose: str = "web_login",
    device_id: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    if not WEB_AUTH_ENABLED:
        return {"ok": False, "error": "web_auth_disabled"}

    contact = (contact or "").strip().lower()
    purpose = (purpose or "web_login").strip() or "web_login"
    if not contact:
        return {"ok": False, "error": "missing_contact"}

    now = _now_utc()
    expires_at = now + timedelta(seconds=WEB_AUTH_OTP_TTL_SECONDS)

    otp = f"{secrets.randbelow(1_000_000):06d}"

    row: Dict[str, Any] = {
        "contact": contact,
        "purpose": purpose,
        "otp_hash": otp_hash(contact, purpose, otp),
        "expires_at": _iso(expires_at),
        "created_at": _iso(now),
    }

    if device_id and _has_column(WEB_OTPS_TABLE, "device_id"):
        row["device_id"] = device_id
    if ip and _has_column(WEB_OTPS_TABLE, "ip"):
        row["ip"] = ip
    if user_agent and _has_column(WEB_OTPS_TABLE, "user_agent"):
        row["user_agent"] = user_agent

    try:
        if _has_column(WEB_OTPS_TABLE, "revoked_at") and _has_column(WEB_OTPS_TABLE, "used_at"):
            (
                _sb()
                .table(WEB_OTPS_TABLE)
                .update({"revoked_at": _iso(now)})
                .eq("contact", contact)
                .eq("purpose", purpose)
                .is_("used_at", "null")
                .is_("revoked_at", "null")
                .execute()
            )
    except Exception:
        pass

    try:
        _sb().table(WEB_OTPS_TABLE).insert(row).execute()
    except Exception as e:
        return {
            "ok": False,
            "error": "otp_insert_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check web_otps schema (otp_hash, expires_at) and RLS permissions.",
            "debug": _safe_debug_meta(),
        }

    out = {"ok": True, "contact": contact, "purpose": purpose, "expires_at": _iso(expires_at)}
    if _truthy(_env("WEB_DEV_RETURN_OTP", "0")) or _env("ENV", "prod").lower() == "dev":
        out["otp_dev"] = otp
    return out


def _create_web_token_row(
    *,
    account_id: str,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    device_id: Optional[str] = None,
) -> Dict[str, Any]:
    raw_token = secrets.token_hex(32)
    th = token_hash(raw_token)
    now = _now_utc()
    expires_at = now + timedelta(days=WEB_AUTH_TOKEN_TTL_DAYS)

    payload: Dict[str, Any] = {
        "account_id": account_id,
        "token_hash": th,
        "expires_at": _iso(expires_at),
    }

    if _has_column(WEB_TOKENS_TABLE, "revoked"):
        payload["revoked"] = False
    if _has_column(WEB_TOKENS_TABLE, "revoked_at"):
        payload["revoked_at"] = None
    if _has_column(WEB_TOKENS_TABLE, "last_seen_at"):
        payload["last_seen_at"] = _iso(now)
    if ip and _has_column(WEB_TOKENS_TABLE, "ip"):
        payload["ip"] = ip
    if user_agent and _has_column(WEB_TOKENS_TABLE, "user_agent"):
        payload["user_agent"] = user_agent
    if device_id and _has_column(WEB_TOKENS_TABLE, "device_id"):
        payload["device_id"] = device_id

    try:
        _sb().table(WEB_TOKENS_TABLE).insert(payload).execute()
    except Exception as e:
        return {
            "ok": False,
            "error": "token_insert_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": (
                "Check FK: web_tokens.account_id must reference accounts.account_id. "
                "Also ensure accounts.account_id is populated for the matching user and UNIQUE."
            ),
            "details": {"account_id": account_id, "token_hash_prefix": th[:12]},
            "debug": _safe_debug_meta(),
        }

    return {"ok": True, "token": raw_token, "expires_at": _iso(expires_at)}


def verify_web_otp_and_issue_token(
    contact: str,
    otp: str,
    purpose: str = "web_login",
    device_id: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    if not WEB_AUTH_ENABLED:
        return {"ok": False, "error": "web_auth_disabled"}

    contact = (contact or "").strip().lower()
    otp = (otp or "").strip()
    purpose = (purpose or "web_login").strip() or "web_login"

    if not contact or not otp:
        return {"ok": False, "error": "missing_contact_or_otp"}

    oh = otp_hash(contact, purpose, otp)
    now = _now_utc()

    try:
        q = (
            _sb()
            .table(WEB_OTPS_TABLE)
            .select("*")
            .eq("contact", contact)
            .eq("purpose", purpose)
            .eq("otp_hash", oh)
            .limit(1)
            .execute()
        )
        rows = getattr(q, "data", None) or []
    except Exception as e:
        return {
            "ok": False,
            "error": "otp_lookup_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check web_otps schema and RLS.",
            "debug": _safe_debug_meta(),
        }

    if not rows:
        return {"ok": False, "error": "invalid_otp"}

    row = rows[0] or {}

    if row.get("used_at"):
        return {"ok": False, "error": "otp_already_used"}
    if row.get("revoked_at"):
        return {"ok": False, "error": "otp_revoked"}

    exp = _parse_iso_dt(row.get("expires_at"))
    if not exp:
        return {
            "ok": False,
            "error": "otp_invalid_expiry",
            "root_cause": "web_otps.expires_at is missing or not ISO format",
            "fix": "Ensure web_otps.expires_at is timestamptz stored as ISO.",
            "debug": _safe_debug_meta(),
        }
    if now > exp:
        return {"ok": False, "error": "otp_expired"}

    try:
        if _has_column(WEB_OTPS_TABLE, "used_at") and row.get("id"):
            _sb().table(WEB_OTPS_TABLE).update({"used_at": _iso(now)}).eq("id", row.get("id")).execute()
    except Exception:
        pass

    acct = ensure_web_account_id(contact)
    if not acct.get("ok"):
        return {
            "ok": False,
            "error": "account_resolve_failed",
            "root_cause": acct.get("root_cause") or acct.get("error"),
            "fix": acct.get("fix") or "Fix accounts identity mapping.",
            "details": acct.get("details") or {"contact": contact},
            "debug": _safe_debug_meta(),
        }

    account_id = str(acct["account_id"]).strip()

    tok = _create_web_token_row(account_id=account_id, ip=ip, user_agent=user_agent, device_id=device_id)
    if not tok.get("ok"):
        return {
            "ok": False,
            "error": "token_issue_failed",
            "root_cause": tok.get("root_cause") or tok.get("error"),
            "fix": tok.get("fix") or "Fix web_tokens insert.",
            "details": tok.get("details") or {},
            "debug": _safe_debug_meta(),
        }

    return {"ok": True, "account_id": account_id, "token": tok["token"], "expires_at": tok["expires_at"]}


def require_web_session(auth_header: str) -> Dict[str, Any]:
    token = _normalize_bearer(auth_header)
    if not token:
        return {"ok": False, "error": "missing_token"}

    th = token_hash(token)
    now = _now_utc()

    try:
        q = _sb().table(WEB_TOKENS_TABLE).select("*").eq("token_hash", th).limit(1).execute()
        rows = getattr(q, "data", None) or []
    except Exception as e:
        return {
            "ok": False,
            "error": "token_lookup_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check web_tokens permissions and correct WEB_TOKEN_PEPPER.",
            "debug": _safe_debug_meta(),
        }

    if not rows:
        return {"ok": False, "error": "invalid_token"}

    row = rows[0] or {}

    if row.get("revoked") is True or row.get("revoked_at"):
        return {"ok": False, "error": "token_revoked"}

    exp = _parse_iso_dt(row.get("expires_at"))
    if not exp:
        return {"ok": False, "error": "token_invalid_expiry", "root_cause": "web_tokens.expires_at missing/bad", "fix": "Ensure web_tokens.expires_at is timestamptz.", "debug": _safe_debug_meta()}
    if now > exp:
        try:
            if _has_column(WEB_TOKENS_TABLE, "revoked"):
                _sb().table(WEB_TOKENS_TABLE).update({"revoked": True}).eq("token_hash", th).execute()
            elif _has_column(WEB_TOKENS_TABLE, "revoked_at"):
                _sb().table(WEB_TOKENS_TABLE).update({"revoked_at": _iso(now)}).eq("token_hash", th).execute()
        except Exception:
            pass
        return {"ok": False, "error": "session_expired"}

    account_id = str(row.get("account_id") or "").strip()
    if not account_id:
        return {
            "ok": False,
            "error": "token_missing_account_id",
            "root_cause": "web_tokens row has empty account_id",
            "fix": "Fix token issuance to always store accounts.account_id.",
            "debug": _safe_debug_meta(),
        }

    try:
        if _has_column(WEB_TOKENS_TABLE, "last_seen_at"):
            _sb().table(WEB_TOKENS_TABLE).update({"last_seen_at": _iso(now)}).eq("token_hash", th).execute()
    except Exception:
        pass

    return {"ok": True, "account_id": account_id, "token_hash_prefix": th[:12]}


def get_account_id_from_request(flask_request) -> Tuple[Optional[str], str]:
    auth = (flask_request.headers.get("Authorization") or "").strip()
    if auth:
        out = require_web_session(auth)
        if out.get("ok"):
            return str(out.get("account_id")), "bearer"

    raw_cookie = (flask_request.cookies.get(WEB_AUTH_COOKIE_NAME) or "").strip()
    if raw_cookie:
        th = token_hash(raw_cookie)
        now = _now_utc()
        try:
            q = _sb().table(WEB_TOKENS_TABLE).select("*").eq("token_hash", th).limit(1).execute()
            rows = getattr(q, "data", None) or []
        except Exception:
            rows = []

        if rows:
            row = rows[0] or {}
            if row.get("revoked") is True or row.get("revoked_at"):
                return None, "cookie"

            exp = _parse_iso_dt(row.get("expires_at"))
            if exp and now <= exp:
                try:
                    if _has_column(WEB_TOKENS_TABLE, "last_seen_at"):
                        _sb().table(WEB_TOKENS_TABLE).update({"last_seen_at": _iso(now)}).eq("token_hash", th).execute()
                except Exception:
                    pass
                aid = str(row.get("account_id") or "").strip()
                return (aid or None), "cookie"

    return None, "none"


def logout_web_session(auth_header: str) -> Dict[str, Any]:
    token = _normalize_bearer(auth_header)
    if not token:
        return {"ok": False, "error": "missing_token"}

    th = token_hash(token)
    now = _now_utc()

    try:
        if _has_column(WEB_TOKENS_TABLE, "revoked"):
            _sb().table(WEB_TOKENS_TABLE).update({"revoked": True}).eq("token_hash", th).execute()
        elif _has_column(WEB_TOKENS_TABLE, "revoked_at"):
            _sb().table(WEB_TOKENS_TABLE).update({"revoked_at": _iso(now)}).eq("token_hash", th).execute()
        else:
            _sb().table(WEB_TOKENS_TABLE).delete().eq("token_hash", th).execute()
    except Exception as e:
        return {
            "ok": False,
            "error": "logout_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check RLS permissions for updating/deleting from web_tokens.",
            "debug": _safe_debug_meta(),
        }

    return {"ok": True}
