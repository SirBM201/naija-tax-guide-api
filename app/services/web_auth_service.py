# app/services/web_auth_service.py
from __future__ import annotations

import hashlib
import os
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Tuple

import requests
from flask import Request

WEB_AUTH_COOKIE_NAME = os.getenv("WEB_AUTH_COOKIE_NAME", "ntg_web_token").strip() or "ntg_web_token"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _pepper() -> str:
    # Pepper makes OTP/token hashes non-reversible even if DB is leaked
    return os.getenv("AUTH_PEPPER", "").strip()


def _otp_ttl_minutes() -> int:
    return int(os.getenv("WEB_OTP_TTL_MINUTES", "10"))


def _token_ttl_days() -> int:
    return int(os.getenv("WEB_TOKEN_TTL_DAYS", "30"))


def _supabase_url() -> str:
    v = (os.getenv("SUPABASE_URL") or "").strip().rstrip("/")
    return v


def _supabase_key() -> str:
    # Use service role key on backend
    return (os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_SERVICE_KEY") or "").strip()


def _postgrest_base() -> str:
    return f"{_supabase_url()}/rest/v1"


def _sb_headers() -> Dict[str, str]:
    key = _supabase_key()
    return {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Prefer": "return=representation",
    }


def _truncate(s: str, n: int = 1200) -> str:
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= n else (s[:n] + "...<truncated>")


def _sb_request(method: str, path: str, *, params: Dict[str, Any] | None = None, json: Any = None) -> Tuple[bool, Any, Dict[str, Any]]:
    """
    Returns: (ok, data, debug)
    debug always includes status + response snippet on failure.
    """
    url = f"{_postgrest_base()}{path}"
    t0 = time.time()
    try:
        res = requests.request(method, url, headers=_sb_headers(), params=params, json=json, timeout=25)
        dt = round((time.time() - t0) * 1000)
        dbg = {
            "url": url,
            "method": method,
            "status": res.status_code,
            "ms": dt,
        }

        # Try JSON parse
        try:
            data = res.json() if res.text else None
        except Exception:
            data = res.text

        if 200 <= res.status_code < 300:
            return True, data, dbg

        dbg["error_body"] = _truncate(res.text)
        return False, data, dbg

    except Exception as e:
        return False, None, {"url": url, "method": method, "status": 0, "exception": repr(e)}


def _hash_otp(otp: str) -> str:
    # Include pepper so hashes can't be brute-forced easily
    return _sha256_hex(f"otp:{otp}:{_pepper()}")


def _hash_token(token: str) -> str:
    return _sha256_hex(f"tok:{token}:{_pepper()}")


def request_web_otp(
    *,
    contact: str,
    purpose: str,
    device_id: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Creates OTP row in public.web_otps and returns metadata.
    In dev, caller may optionally expose _otp_plain.
    """
    contact = (contact or "").strip().lower()
    purpose = (purpose or "web_login").strip().lower()

    if not _supabase_url() or not _supabase_key():
        return {"ok": False, "error": "supabase_not_configured", "root_cause": "Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY"}

    otp_plain = f"{secrets.randbelow(1000000):06d}"
    expires_at = _now_utc() + timedelta(minutes=_otp_ttl_minutes())

    row = {
        "contact": contact,
        "purpose": purpose,
        "code_hash": _hash_otp(otp_plain),
        "expires_at": expires_at.isoformat(),
        "used": False,
        "attempts": 0,
        "last_attempt_at": None,
        "locked_until": None,
        "request_ip": ip,
        "channel": "email",
        "sent_to": contact,
    }

    ok, data, dbg = _sb_request("POST", "/web_otps", json=row)
    if not ok:
        return {"ok": False, "error": "otp_insert_failed", "root_cause": dbg.get("error_body") or data, "debug": dbg}

    created = data[0] if isinstance(data, list) and data else data
    return {
        "ok": True,
        "contact": contact,
        "purpose": purpose,
        "expires_at": expires_at.isoformat(),
        "_otp_plain": otp_plain,
        "debug": {
            "received": {
                "device_id": device_id,
                "ip": ip,
                "user_agent_present": bool(user_agent),
            },
            "tables": {"otp_table": "web_otps", "token_table": "web_tokens"},
            "supabase": dbg,
            "otp_row_id": (created or {}).get("id"),
        },
    }


def _find_latest_otp(contact: str, purpose: str) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    params = {
        "select": "id,code_hash,expires_at,used,used_at,attempts,locked_until,created_at",
        "contact": f"eq.{contact}",
        "purpose": f"eq.{purpose}",
        "order": "created_at.desc",
        "limit": "10",
    }
    ok, data, dbg = _sb_request("GET", "/web_otps", params=params)
    if not ok:
        return None, {"error": "otp_lookup_failed", "root_cause": dbg.get("error_body") or data, "debug": dbg}

    rows = data if isinstance(data, list) else []
    return (rows[0] if rows else None), {"debug": dbg}


def _mark_otp_used(otp_id: str) -> Optional[Dict[str, Any]]:
    ok, data, dbg = _sb_request("PATCH", f"/web_otps?id=eq.{otp_id}", json={"used": True, "used_at": _now_utc().isoformat()})
    if ok:
        return {"ok": True}
    return {"ok": False, "root_cause": dbg.get("error_body") or data, "debug": dbg}


def _get_or_create_web_account(contact: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Returns the account row from 'accounts' for provider='web'.
    Your schema currently has BOTH 'id' and 'account_id'.
    """
    # Try fetch first
    params = {
        "select": "id,account_id,provider,provider_user_id",
        "provider": "eq.web",
        "provider_user_id": f"eq.{contact}",
        "limit": "1",
    }
    ok, data, dbg = _sb_request("GET", "/accounts", params=params)
    if not ok:
        return None, {"error": "account_lookup_failed", "root_cause": dbg.get("error_body") or data, "debug": dbg}

    rows = data if isinstance(data, list) else []
    if rows:
        return rows[0], None

    # Create row (minimal fields)
    row = {
        "provider": "web",
        "provider_user_id": contact,
    }
    ok, data, dbg = _sb_request("POST", "/accounts", json=row)
    if not ok:
        return None, {"error": "account_create_failed", "root_cause": dbg.get("error_body") or data, "debug": dbg}

    created = data[0] if isinstance(data, list) and data else data
    return created, None


def _insert_web_token_with_fallback(account_row: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Defensive token insert:
    - First tries accounts.id
    - If FK complains, tries accounts.account_id
    This protects you from schema drift (exactly what happened).
    """
    token_plain = secrets.token_urlsafe(48)
    token_hash = _hash_token(token_plain)
    expires_at = (_now_utc() + timedelta(days=_token_ttl_days())).isoformat()

    candidates = []
    if account_row.get("id"):
        candidates.append(("accounts.id", account_row["id"]))
    if account_row.get("account_id"):
        candidates.append(("accounts.account_id", account_row["account_id"]))

    last_err: Optional[Dict[str, Any]] = None

    for label, acct_value in candidates:
        payload = {
            "token_hash": token_hash,
            "account_id": acct_value,
            "expires_at": expires_at,
            "revoked": False,
        }

        ok, data, dbg = _sb_request("POST", "/web_tokens", json=payload)
        if ok:
            created = data[0] if isinstance(data, list) and data else data
            return {
                "ok": True,
                "token": token_plain,
                "token_hash": token_hash,
                "expires_at": expires_at,
                "account_id": acct_value,
                "account_id_source": label,
                "token_row_id": (created or {}).get("id"),
            }, None

        # keep error for root cause exposure
        last_err = {
            "error": "web_token_insert_failed",
            "attempt": label,
            "root_cause": dbg.get("error_body") or data,
            "debug": dbg,
        }

    return None, last_err or {"error": "web_token_insert_failed", "root_cause": "No account id candidates available"}


def verify_web_otp_and_issue_token(*, contact: str, otp: str, purpose: str) -> Dict[str, Any]:
    contact = (contact or "").strip().lower()
    purpose = (purpose or "web_login").strip().lower()
    otp = (otp or "").strip()

    if not contact or not otp:
        return {"ok": False, "error": "contact_and_otp_required"}

    if not _supabase_url() or not _supabase_key():
        return {"ok": False, "error": "supabase_not_configured", "root_cause": "Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY"}

    otp_row, otp_dbg = _find_latest_otp(contact, purpose)
    if not otp_row:
        return {"ok": False, "error": "otp_not_found", **otp_dbg}

    if otp_row.get("used") is True:
        return {"ok": False, "error": "otp_already_used", "otp_id": otp_row.get("id")}

    # expiry check
    try:
        exp = otp_row["expires_at"]
        exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        if _now_utc() >= exp_dt:
            return {"ok": False, "error": "otp_expired", "expires_at": exp}
    except Exception as e:
        return {"ok": False, "error": "otp_expiry_parse_failed", "root_cause": repr(e), "otp_row": otp_row}

    # verify hash
    if _hash_otp(otp) != (otp_row.get("code_hash") or ""):
        return {"ok": False, "error": "otp_invalid", "otp_id": otp_row.get("id")}

    # mark used
    used_res = _mark_otp_used(otp_row["id"])
    if used_res and not used_res.get("ok"):
        return {"ok": False, "error": "otp_mark_used_failed", "root_cause": used_res.get("root_cause"), "debug": used_res.get("debug")}

    # get or create account
    acct, acct_err = _get_or_create_web_account(contact)
    if acct_err:
        return {"ok": False, **acct_err}

    # insert token (with fallback between id vs account_id)
    token_res, token_err = _insert_web_token_with_fallback(acct)
    if token_err:
        return {"ok": False, "error": "token_issue_failed", **token_err, "account_row": acct}

    return {
        "ok": True,
        "account_id": token_res["account_id"],
        "token": token_res["token"],
        "expires_at": token_res["expires_at"],
        "debug": {
            "otp_id": otp_row.get("id"),
            "account_row": {"id": acct.get("id"), "account_id": acct.get("account_id")},
            "insert_used_account_id_source": token_res.get("account_id_source"),
        },
    }


def _extract_token_from_request(req: Request) -> Tuple[str, Dict[str, Any]]:
    debug: Dict[str, Any] = {"token_source": None}

    h = (req.headers.get("Authorization") or "").strip()
    if h.lower().startswith("bearer "):
        debug["token_source"] = "bearer"
        return h[7:].strip(), debug

    c = (req.cookies.get(WEB_AUTH_COOKIE_NAME) or "").strip()
    if c:
        debug["token_source"] = "cookie"
        return c, debug

    return "", debug


def get_account_id_from_request(req: Request) -> Tuple[Optional[str], Dict[str, Any]]:
    token, dbg = _extract_token_from_request(req)
    if not token:
        return None, {"ok": False, "error": "missing_token", **dbg}

    token_hash = _hash_token(token)

    params = {
        "select": "id,account_id,expires_at,revoked",
        "token_hash": f"eq.{token_hash}",
        "limit": "1",
    }
    ok, data, sb_dbg = _sb_request("GET", "/web_tokens", params=params)
    if not ok:
        return None, {"ok": False, "error": "token_lookup_failed", "root_cause": sb_dbg.get("error_body") or data, "debug": sb_dbg, **dbg}

    rows = data if isinstance(data, list) else []
    if not rows:
        return None, {"ok": False, "error": "invalid_token", **dbg}

    row = rows[0]
    if row.get("revoked") is True:
        return None, {"ok": False, "error": "token_revoked", **dbg}

    try:
        exp_dt = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
        if _now_utc() >= exp_dt:
            return None, {"ok": False, "error": "token_expired", "expires_at": row.get("expires_at"), **dbg}
    except Exception as e:
        return None, {"ok": False, "error": "token_expiry_parse_failed", "root_cause": repr(e), "token_row": row, **dbg}

    # update last_seen_at (non-fatal)
    _sb_request("PATCH", f"/web_tokens?id=eq.{row.get('id')}", json={"last_seen_at": _now_utc().isoformat()})

    return str(row.get("account_id")), {"ok": True, **dbg}


def logout_web_session(req: Request) -> Dict[str, Any]:
    token, dbg = _extract_token_from_request(req)
    if not token:
        return {"ok": True, "logged_out": False, "reason": "no_token", **dbg}

    token_hash = _hash_token(token)

    # revoke any matching token rows
    ok, data, sb_dbg = _sb_request("PATCH", f"/web_tokens?token_hash=eq.{token_hash}", json={"revoked": True})
    if not ok:
        return {"ok": False, "error": "logout_failed", "root_cause": sb_dbg.get("error_body") or data, "debug": sb_dbg, **dbg}

    return {"ok": True, "logged_out": True, **dbg}
