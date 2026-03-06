# app/services/web_auth_service.py
from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Tuple, List

import requests
from flask import Request

from app.core.config import (
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY,
    WEB_AUTH_COOKIE_NAME,
    WEB_TOKEN_PEPPER,
    WEB_OTP_PEPPER,
    WEB_OTP_TTL_MINUTES,
    WEB_SESSION_TTL_DAYS,
    WEB_OTP_TABLE,
    WEB_TOKEN_TABLE,
)

TOKEN_INSERT_MAX_RETRIES = int((__import__("os").getenv("WEB_TOKEN_INSERT_MAX_RETRIES", "5") or "5"))
TOKEN_INSERT_RETRY_SLEEP_MS = int((__import__("os").getenv("WEB_TOKEN_INSERT_RETRY_SLEEP_MS", "50") or "50"))

REVOKE_OLD_TOKENS_ON_LOGIN = str(__import__("os").getenv("WEB_REVOKE_OLD_TOKENS_ON_LOGIN", "1")).strip().lower() in {
    "1", "true", "yes", "y", "on"
}

BEARER_FALLBACK_TO_COOKIE = str(__import__("os").getenv("WEB_BEARER_FALLBACK_TO_COOKIE", "1")).strip().lower() in {
    "1", "true", "yes", "y", "on"
}


# -------------------- time / hashing --------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _otp_pepper() -> str:
    return (WEB_OTP_PEPPER or "").strip()


def _token_pepper() -> str:
    return (WEB_TOKEN_PEPPER or "").strip()


def _hash_otp(otp: str) -> str:
    return _sha256_hex(f"otp:{otp}:{_otp_pepper()}")


def _hash_token(token: str) -> str:
    # IMPORTANT: must match app/core/auth.py
    return _sha256_hex(f"tok:{token}:{_token_pepper()}")


def _truncate(s: Any, n: int = 1800) -> str:
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= n else (s[:n] + "...<truncated>")


# -------------------- supabase postgrest --------------------

def _postgrest_base() -> str:
    url = (SUPABASE_URL or "").strip().rstrip("/")
    if not url:
        raise RuntimeError("SUPABASE_URL is missing")
    return f"{url}/rest/v1"


def _service_key() -> str:
    key = (SUPABASE_SERVICE_ROLE_KEY or "").strip()
    if not key:
        raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY is missing")
    return key


def _sb_headers() -> Dict[str, str]:
    key = _service_key()
    return {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Prefer": "return=representation",
    }


def _sb_request(
    method: str,
    path: str,
    *,
    params: Dict[str, Any] | None = None,
    json: Any = None,
) -> Tuple[bool, Any, Dict[str, Any]]:
    url = f"{_postgrest_base()}{path}"
    t0 = time.time()
    try:
        res = requests.request(method, url, headers=_sb_headers(), params=params, json=json, timeout=25)
        dt = round((time.time() - t0) * 1000)

        dbg: Dict[str, Any] = {"url": url, "method": method, "status": res.status_code, "ms": dt}

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


# -------------------- error helper --------------------

def _fail(*, stage: str, error: str, root_cause: Any = None, debug: Any = None, extra: Dict[str, Any] | None = None):
    out: Dict[str, Any] = {"ok": False, "error": error, "stage": stage}
    if root_cause is not None:
        out["root_cause"] = root_cause
    if debug is not None:
        out["debug"] = debug
    if extra:
        out.update(extra)
    return out


def _looks_like_unique_violation(dbg: Dict[str, Any]) -> bool:
    body = (dbg.get("error_body") or "")
    return ("23505" in body) or (dbg.get("status") == 409) or ("duplicate key" in body.lower()) or ("unique" in body.lower())


# -------------------- OTP Request --------------------

def request_web_otp(
    *,
    contact: str,
    purpose: str,
    device_id: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    contact = (contact or "").strip().lower()
    purpose = (purpose or "web_login").strip().lower()

    if "@" not in contact:
        return _fail(stage="validate_contact", error="invalid_contact_email", extra={"contact": contact})

    otp_plain = f"{secrets.randbelow(1000000):06d}"
    expires_at = _now_utc() + timedelta(minutes=int(WEB_OTP_TTL_MINUTES or 10))

    # IMPORTANT:
    # only include columns that exist in your current web_otps table
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

    ok, data, dbg = _sb_request("POST", f"/{WEB_OTP_TABLE}", json=row)
    if not ok:
        return _fail(stage="otp_insert", error="otp_insert_failed", root_cause=dbg.get("error_body") or data, debug=dbg)

    created = data[0] if isinstance(data, list) and data else data
    return {
        "ok": True,
        "contact": contact,
        "purpose": purpose,
        "expires_at": expires_at.isoformat(),
        "_otp_plain": otp_plain,
        "debug": {
            "tables": {"otp_table": WEB_OTP_TABLE, "token_table": WEB_TOKEN_TABLE, "accounts_table": "accounts"},
            "supabase": dbg,
            "otp_row_id": (created or {}).get("id"),
            "received": {
                "device_id_present": bool(device_id),
                "ip_present": bool(ip),
                "user_agent_present": bool(user_agent),
            },
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
    ok, data, dbg = _sb_request("GET", f"/{WEB_OTP_TABLE}", params=params)
    if not ok:
        return None, _fail(stage="otp_lookup", error="otp_lookup_failed", root_cause=dbg.get("error_body") or data, debug=dbg)

    rows = data if isinstance(data, list) else []
    return (rows[0] if rows else None), {"ok": True, "debug": dbg}


def _mark_otp_used(otp_id: str) -> Dict[str, Any]:
    ok, data, dbg = _sb_request(
        "PATCH",
        f"/{WEB_OTP_TABLE}?id=eq.{otp_id}",
        json={"used": True, "used_at": _now_utc().isoformat()},
    )
    if ok:
        return {"ok": True}
    return _fail(stage="otp_mark_used", error="otp_mark_used_failed", root_cause=dbg.get("error_body") or data, debug=dbg)


# -------------------- Accounts --------------------

def _patch_account(accounts_row_id: str, patch: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    ok, data, dbg = _sb_request("PATCH", f"/accounts?id=eq.{accounts_row_id}", json=patch)
    if not ok:
        return False, _fail(stage="account_patch", error="account_patch_failed", root_cause=dbg.get("error_body") or data, debug=dbg)
    return True, {"ok": True, "supabase": dbg}


def _get_or_create_web_account(contact: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    contact = (contact or "").strip().lower()

    params = {
        "select": "id,account_id,provider,provider_user_id,email,created_at,updated_at",
        "provider": "eq.web",
        "provider_user_id": f"eq.{contact}",
        "limit": "1",
    }
    ok, data, dbg = _sb_request("GET", "/accounts", params=params)
    if not ok:
        return None, _fail(stage="account_lookup", error="account_lookup_failed", root_cause=dbg.get("error_body") or data, debug=dbg)

    rows = data if isinstance(data, list) else []
    if rows:
        acct = rows[0] or {}
        row_id = str(acct.get("id") or "").strip()
        acct_id = str(acct.get("account_id") or "").strip()
        email = str(acct.get("email") or "").strip().lower()

        patch: Dict[str, Any] = {}
        if row_id and not email:
            patch["email"] = contact
        if row_id and not acct_id:
            patch["account_id"] = row_id

        if patch:
            patch["updated_at"] = _now_utc().isoformat()
            ok2, info = _patch_account(row_id, patch)
            if not ok2:
                acct["_repair_warning"] = info
            else:
                acct.update(patch)

        return acct, None

    new_id = str(uuid.uuid4())
    row = {
        "id": new_id,
        "account_id": new_id,
        "provider": "web",
        "provider_user_id": contact,
        "email": contact,
        "created_at": _now_utc().isoformat(),
        "updated_at": _now_utc().isoformat(),
    }
    ok3, data3, dbg3 = _sb_request("POST", "/accounts", json=row)
    if not ok3:
        return None, _fail(stage="account_create", error="account_create_failed", root_cause=dbg3.get("error_body") or data3, debug=dbg3)

    created = data3[0] if isinstance(data3, list) and data3 else data3
    return created, None


# -------------------- Sessions --------------------

def _revoke_all_sessions_for_account(account_id: str) -> None:
    _sb_request("PATCH", f"/{WEB_TOKEN_TABLE}?account_id=eq.{account_id}", json={"revoked": True, "revoked_at": _now_utc().isoformat()})


def _insert_web_session(*, account_id: str, ip: Optional[str], user_agent: Optional[str]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    expires_at = (_now_utc() + timedelta(days=int(WEB_SESSION_TTL_DAYS or 30))).isoformat()

    attempts: List[Dict[str, Any]] = []

    for n in range(1, TOKEN_INSERT_MAX_RETRIES + 1):
        token_plain = secrets.token_urlsafe(48)
        token_hash = _hash_token(token_plain)

        payload = {
            "token_hash": token_hash,
            "account_id": account_id,
            "expires_at": expires_at,
            "revoked": False,
            "ip": ip,
            "user_agent": user_agent,
        }

        ok, data, dbg = _sb_request("POST", f"/{WEB_TOKEN_TABLE}", json=payload)
        if ok:
            created = data[0] if isinstance(data, list) and data else data
            return {
                "ok": True,
                "token": token_plain,
                "token_hash": token_hash,
                "expires_at": expires_at,
                "session_row_id": (created or {}).get("id"),
                "account_id": account_id,
            }, None

        attempts.append({"try": n, "status": dbg.get("status"), "root_cause": dbg.get("error_body") or data, "supabase": dbg})

        if _looks_like_unique_violation(dbg):
            if TOKEN_INSERT_RETRY_SLEEP_MS > 0:
                time.sleep(TOKEN_INSERT_RETRY_SLEEP_MS / 1000.0)
            continue

        break

    return None, _fail(stage="session_insert", error="web_session_insert_failed", root_cause="insert_failed", extra={"attempts": attempts})


def verify_web_otp_and_issue_token(*, contact: str, otp: str, purpose: str, ip: Optional[str] = None, user_agent: Optional[str] = None) -> Dict[str, Any]:
    contact = (contact or "").strip().lower()
    purpose = (purpose or "web_login").strip().lower()
    otp = (otp or "").strip()

    if not contact or not otp:
        return _fail(stage="validate_input", error="contact_and_otp_required")

    if "@" not in contact:
        return _fail(stage="validate_contact", error="invalid_contact_email", extra={"contact": contact})

    otp_row, otp_dbg = _find_latest_otp(contact, purpose)
    if not otp_row:
        return _fail(stage="otp_lookup", error="otp_not_found", debug=otp_dbg)

    if otp_row.get("used") is True:
        return _fail(stage="otp_state", error="otp_already_used", extra={"otp_id": otp_row.get("id")})

    try:
        exp = str(otp_row["expires_at"])
        exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        if _now_utc() >= exp_dt:
            return _fail(stage="otp_expiry", error="otp_expired", extra={"expires_at": exp, "otp_id": otp_row.get("id")})
    except Exception as e:
        return _fail(stage="otp_expiry_parse", error="otp_expiry_parse_failed", root_cause=repr(e), extra={"otp_row": otp_row})

    if _hash_otp(otp) != (otp_row.get("code_hash") or ""):
        return _fail(stage="otp_compare", error="otp_invalid", extra={"otp_id": otp_row.get("id")})

    used_res = _mark_otp_used(str(otp_row["id"]))
    if not used_res.get("ok"):
        return _fail(stage="otp_mark_used", error="otp_mark_used_failed", root_cause=used_res.get("root_cause"), debug=used_res.get("debug"))

    acct, acct_err = _get_or_create_web_account(contact)
    if acct_err:
        return {"ok": False, **acct_err}

    canonical_account_id = str(acct.get("account_id") or acct.get("id") or "").strip()
    if not canonical_account_id:
        return _fail(stage="account_state", error="account_id_missing", extra={"account_row": acct})

    if REVOKE_OLD_TOKENS_ON_LOGIN:
        try:
            _revoke_all_sessions_for_account(canonical_account_id)
        except Exception:
            pass

    sess_res, sess_err = _insert_web_session(account_id=canonical_account_id, ip=ip, user_agent=user_agent)
    if sess_err:
        return {"ok": False, **sess_err}

    return {
        "ok": True,
        "account_id": canonical_account_id,
        "token": str(sess_res["token"]),
        "expires_at": str(sess_res["expires_at"]),
        "debug": {
            "otp_id": otp_row.get("id"),
            "account_row": {
                "id": acct.get("id"),
                "account_id": acct.get("account_id"),
                "provider": acct.get("provider"),
                "provider_user_id": acct.get("provider_user_id"),
                "email": acct.get("email") or contact,
                "repair_warning": acct.get("_repair_warning"),
            },
            "session_insert": {
                "table": WEB_TOKEN_TABLE,
                "session_row_id": sess_res.get("session_row_id"),
                "account_id": sess_res.get("account_id"),
            },
        },
    }


# -------------------- Token extraction / auth --------------------

def _extract_token_candidates(req: Request) -> Tuple[str, str, Dict[str, Any]]:
    debug: Dict[str, Any] = {
        "token_source": None,
        "has_bearer": False,
        "has_cookie": False,
        "origin": (req.headers.get("Origin") or "").strip() or None,
        "host": (req.headers.get("Host") or "").strip() or None,
    }

    h = (req.headers.get("Authorization") or "").strip()
    bearer = ""
    if h.lower().startswith("bearer "):
        bearer = h[7:].strip()
        debug["has_bearer"] = bool(bearer)

    cookie = (req.cookies.get(WEB_AUTH_COOKIE_NAME) or "").strip()
    debug["has_cookie"] = bool(cookie)

    return bearer, cookie, debug


def _lookup_token_plain(token_plain: str) -> Tuple[Optional[str], Dict[str, Any]]:
    token_hash = _hash_token(token_plain)

    params = {
        "select": "id,account_id,expires_at,revoked,revoked_at,last_seen_at,created_at",
        "token_hash": f"eq.{token_hash}",
        "limit": "1",
    }
    ok, data, sb_dbg = _sb_request("GET", f"/{WEB_TOKEN_TABLE}", params=params)
    if not ok:
        return None, _fail(stage="token_lookup", error="token_lookup_failed", root_cause=sb_dbg.get("error_body") or data, debug=sb_dbg)

    rows = data if isinstance(data, list) else []
    if not rows:
        return None, _fail(stage="token_lookup", error="invalid_token", debug={"supabase": sb_dbg})

    row = rows[0]
    if row.get("revoked") is True:
        return None, _fail(stage="token_state", error="token_revoked", debug={"supabase": sb_dbg})

    try:
        exp_dt = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
        if _now_utc() >= exp_dt:
            return None, _fail(stage="token_expiry", error="token_expired", extra={"expires_at": row.get("expires_at")}, debug={"supabase": sb_dbg})
    except Exception as e:
        return None, _fail(stage="token_expiry_parse", error="token_expiry_parse_failed", root_cause=repr(e), extra={"token_row": row}, debug={"supabase": sb_dbg})

    account_id = str(row.get("account_id") or "").strip() or None
    if not account_id:
        return None, _fail(stage="token_state", error="token_missing_account_id", extra={"token_row": row}, debug={"supabase": sb_dbg})

    try:
        _sb_request("PATCH", f"/{WEB_TOKEN_TABLE}?id=eq.{row.get('id')}", json={"last_seen_at": _now_utc().isoformat()})
    except Exception:
        pass

    return account_id, {"ok": True, "debug": {"supabase": sb_dbg}}


def get_account_id_from_request(req: Request) -> Tuple[Optional[str], Dict[str, Any]]:
    bearer, cookie, src_dbg = _extract_token_candidates(req)

    if not bearer and not cookie:
        return None, {"ok": False, "error": "missing_token", **src_dbg}

    if bearer:
        acc, dbg = _lookup_token_plain(bearer)
        if acc:
            return acc, {"ok": True, "token_source": "bearer", **src_dbg, "debug": dbg.get("debug")}

        if BEARER_FALLBACK_TO_COOKIE and cookie:
            acc2, dbg2 = _lookup_token_plain(cookie)
            if acc2:
                return acc2, {"ok": True, "token_source": "cookie_fallback", **src_dbg, "debug": dbg2.get("debug")}

        return None, {"ok": False, "error": "invalid_token", "token_source": "bearer", **src_dbg}

    acc3, dbg3 = _lookup_token_plain(cookie)
    if acc3:
        return acc3, {"ok": True, "token_source": "cookie", **src_dbg, "debug": dbg3.get("debug")}

    return None, {"ok": False, "error": "invalid_token", "token_source": "cookie", **src_dbg}


def logout_web_session(req: Request) -> Dict[str, Any]:
    bearer, cookie, src_dbg = _extract_token_candidates(req)
    token = bearer or cookie
    if not token:
        return {"ok": True, "logged_out": False, "reason": "no_token", **src_dbg}

    token_hash = _hash_token(token)

    ok, data, sb_dbg = _sb_request("PATCH", f"/{WEB_TOKEN_TABLE}?token_hash=eq.{token_hash}", json={"revoked": True, "revoked_at": _now_utc().isoformat()})
    if not ok:
        return _fail(stage="logout", error="logout_failed", root_cause=sb_dbg.get("error_body") or data, debug=sb_dbg, extra=src_dbg)

    return {"ok": True, "logged_out": True, **src_dbg}
