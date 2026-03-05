# app/services/web_auth_service.py
from __future__ import annotations

import hashlib
import os
import secrets
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Tuple, List

import requests
from flask import Request

# -------------------- ENV / TABLE NAMES --------------------

WEB_AUTH_COOKIE_NAME = (os.getenv("WEB_AUTH_COOKIE_NAME", "ntg_web_token").strip() or "ntg_web_token")

# Table names (overrideable)
ACCOUNTS_TABLE = (os.getenv("ACCOUNTS_TABLE", "accounts").strip() or "accounts")
WEB_OTP_TABLE = (os.getenv("WEB_OTP_TABLE", "web_otps").strip() or "web_otps")
WEB_TOKEN_TABLE = (os.getenv("WEB_TOKEN_TABLE", "web_tokens").strip() or "web_tokens")

TOKEN_INSERT_MAX_RETRIES = int(os.getenv("WEB_TOKEN_INSERT_MAX_RETRIES", "5") or "5")
TOKEN_INSERT_RETRY_SLEEP_MS = int(os.getenv("WEB_TOKEN_INSERT_RETRY_SLEEP_MS", "50") or "50")

REVOKE_OLD_TOKENS_ON_LOGIN = str(os.getenv("WEB_REVOKE_OLD_TOKENS_ON_LOGIN", "1")).strip().lower() in {
    "1", "true", "yes", "y", "on"
}

BEARER_FALLBACK_TO_COOKIE = str(os.getenv("WEB_BEARER_FALLBACK_TO_COOKIE", "1")).strip().lower() in {
    "1", "true", "yes", "y", "on"
}


# -------------------- time / hashing --------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _require_env(*names: str) -> str:
    for n in names:
        v = (os.getenv(n) or "").strip()
        if v:
            return v
    raise RuntimeError(f"Missing required env var. Provide one of: {', '.join(names)}")


def _otp_pepper() -> str:
    return _require_env("WEB_OTP_PEPPER", "OTP_HASH_PEPPER")


def _token_pepper() -> str:
    return _require_env("WEB_TOKEN_PEPPER")


def _otp_ttl_minutes() -> int:
    return int(os.getenv("WEB_OTP_TTL_MINUTES", "10") or "10")


def _token_ttl_days() -> int:
    return int(os.getenv("WEB_TOKEN_TTL_DAYS", "30") or "30")


# -------------------- supabase rest --------------------

def _supabase_url() -> str:
    url = (os.getenv("SUPABASE_URL") or "").strip().rstrip("/")
    if not url:
        raise RuntimeError("SUPABASE_URL is missing")
    return url


def _supabase_key() -> str:
    key = (os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_SERVICE_KEY") or "").strip()
    if not key:
        raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY is missing")
    return key


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


def _truncate(s: Any, n: int = 1800) -> str:
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= n else (s[:n] + "...<truncated>")


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


# -------------------- errors (failure exposure) --------------------

def _fail(*, stage: str, error: str, root_cause: Any = None, debug: Any = None, extra: Dict[str, Any] | None = None):
    out: Dict[str, Any] = {"ok": False, "error": error, "stage": stage}
    if root_cause is not None:
        out["root_cause"] = root_cause
    if debug is not None:
        out["debug"] = debug
    if extra:
        out.update(extra)
    return out


# -------------------- hashing helpers --------------------

def _hash_otp(otp: str) -> str:
    return _sha256_hex(f"otp:{otp}:{_otp_pepper()}")


def _hash_token(token: str) -> str:
    return _sha256_hex(f"tok:{token}:{_token_pepper()}")


def _looks_like_fk_violation(dbg: Dict[str, Any]) -> bool:
    body = (dbg.get("error_body") or "")
    return ("23503" in body) or ("foreign key" in body.lower()) or ("violates foreign key" in body.lower())


def _looks_like_unique_violation(dbg: Dict[str, Any]) -> bool:
    body = (dbg.get("error_body") or "")
    return ("23505" in body) or (dbg.get("status") == 409) or ("duplicate key" in body.lower()) or ("unique" in body.lower())


def _looks_like_email(v: str) -> bool:
    v = (v or "").strip().lower()
    return ("@" in v) and ("." in v.split("@")[-1])


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

    ok, data, dbg = _sb_request("POST", f"/{WEB_OTP_TABLE}", json=row)
    if not ok:
        return _fail(
            stage="otp_insert",
            error="otp_insert_failed",
            root_cause=dbg.get("error_body") or data,
            debug=dbg,
        )

    created = data[0] if isinstance(data, list) and data else data
    return {
        "ok": True,
        "contact": contact,
        "purpose": purpose,
        "expires_at": expires_at.isoformat(),
        "_otp_plain": otp_plain,
        "debug": {
            "received": {"device_id": device_id, "ip": ip, "user_agent_present": bool(user_agent)},
            "tables": {"otp_table": WEB_OTP_TABLE, "token_table": WEB_TOKEN_TABLE, "accounts_table": ACCOUNTS_TABLE},
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


# -------------------- Accounts (email persistence + canonical account_id) --------------------

def _ensure_account_email(accounts_id: str, contact_email: str) -> Tuple[bool, Dict[str, Any]]:
    """
    Ensures accounts.email is set.
    If email already set, does nothing.
    If missing/blank, patches it.

    Returns (ok, debug/err dict)
    """
    params = {"select": "id,email,provider_user_id", "id": f"eq.{accounts_id}", "limit": "1"}
    ok, data, dbg = _sb_request("GET", f"/{ACCOUNTS_TABLE}", params=params)
    if not ok:
        return False, _fail(stage="accounts_email_read", error="accounts_email_read_failed", root_cause=dbg.get("error_body") or data, debug=dbg)

    rows = data if isinstance(data, list) else []
    current = rows[0] if rows else {}
    existing_email = (current.get("email") or "").strip().lower()

    if existing_email:
        return True, {"ok": True, "already_set": True, "email": existing_email}

    patch = {"email": contact_email, "updated_at": _now_utc().isoformat()}
    ok2, data2, dbg2 = _sb_request("PATCH", f"/{ACCOUNTS_TABLE}?id=eq.{accounts_id}", json=patch)
    if not ok2:
        return False, _fail(stage="accounts_email_patch", error="accounts_email_patch_failed", root_cause=dbg2.get("error_body") or data2, debug=dbg2)

    return True, {"ok": True, "updated": True, "email": contact_email, "supabase": dbg2}


def _ensure_account_account_id(accounts_id: str) -> Tuple[bool, Dict[str, Any]]:
    """
    Ensures accounts.account_id is populated (canonical identity).
    If account_id is NULL/blank, set it to id.
    """
    params = {"select": "id,account_id", "id": f"eq.{accounts_id}", "limit": "1"}
    ok, data, dbg = _sb_request("GET", f"/{ACCOUNTS_TABLE}", params=params)
    if not ok:
        return False, _fail(stage="accounts_account_id_read", error="accounts_account_id_read_failed", root_cause=dbg.get("error_body") or data, debug=dbg)

    rows = data if isinstance(data, list) else []
    row = rows[0] if rows else {}
    current = (row.get("account_id") or "").strip()

    if current:
        return True, {"ok": True, "already_set": True, "account_id": current}

    patch = {"account_id": accounts_id, "updated_at": _now_utc().isoformat()}
    ok2, data2, dbg2 = _sb_request("PATCH", f"/{ACCOUNTS_TABLE}?id=eq.{accounts_id}", json=patch)
    if not ok2:
        return False, _fail(stage="accounts_account_id_patch", error="accounts_account_id_patch_failed", root_cause=dbg2.get("error_body") or data2, debug=dbg2)

    return True, {"ok": True, "updated": True, "account_id": accounts_id, "supabase": dbg2}


def _get_or_create_web_account(contact: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Accounts table expected:
      - provider = 'web'
      - provider_user_id = contact (email)
      - email column exists and will be stored/backfilled
      - account_id column (canonical) is ensured to be populated (set to id if NULL)
    """
    params = {
        "select": "id,account_id,provider,provider_user_id,email,created_at,updated_at,display_name",
        "provider": "eq.web",
        "provider_user_id": f"eq.{contact}",
        "limit": "1",
    }
    ok, data, dbg = _sb_request("GET", f"/{ACCOUNTS_TABLE}", params=params)
    if not ok:
        return None, _fail(stage="account_lookup", error="account_lookup_failed", root_cause=dbg.get("error_body") or data, debug=dbg)

    rows = data if isinstance(data, list) else []
    if rows:
        acct = rows[0] or {}
        accounts_id = str(acct.get("id") or "").strip()

        warnings: Dict[str, Any] = {}
        if accounts_id:
            ok_e, info_e = _ensure_account_email(accounts_id, contact)
            if not ok_e:
                warnings["email"] = info_e

            ok_a, info_a = _ensure_account_account_id(accounts_id)
            if not ok_a:
                warnings["account_id"] = info_a

        if warnings:
            acct["_persist_warnings"] = warnings

        return acct, None

    # Create new account row WITH email.
    # account_id may be NULL depending on DB defaults, so we patch it after insert.
    row = {
        "provider": "web",
        "provider_user_id": contact,
        "email": contact,
        "display_name": contact,
        "created_at": _now_utc().isoformat(),
        "updated_at": _now_utc().isoformat(),
    }
    ok, data, dbg = _sb_request("POST", f"/{ACCOUNTS_TABLE}", json=row)
    if not ok:
        return None, _fail(stage="account_create", error="account_create_failed", root_cause=dbg.get("error_body") or data, debug=dbg)

    created = data[0] if isinstance(data, list) and data else (data or {})
    accounts_id = str((created or {}).get("id") or "").strip()

    warnings: Dict[str, Any] = {}
    if accounts_id:
        ok_a, info_a = _ensure_account_account_id(accounts_id)
        if not ok_a:
            warnings["account_id"] = info_a

    if warnings:
        created["_persist_warnings"] = warnings

    return created, None


# -------------------- Tokens --------------------

def _revoke_all_tokens_for_account(accounts_id: str) -> None:
    # Best-effort
    _sb_request("PATCH", f"/{WEB_TOKEN_TABLE}?account_id=eq.{accounts_id}", json={"revoked": True})


def _insert_web_token(account_row: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    accounts_id = str(account_row["id"])
    expires_at = (_now_utc() + timedelta(days=_token_ttl_days())).isoformat()

    attempts: List[Dict[str, Any]] = []

    for n in range(1, TOKEN_INSERT_MAX_RETRIES + 1):
        token_plain = secrets.token_urlsafe(48)
        token_hash = _hash_token(token_plain)

        payload = {
            "token_hash": token_hash,
            "account_id": accounts_id,  # FK -> accounts.id
            "expires_at": expires_at,
            "revoked": False,
        }

        ok, data, dbg = _sb_request("POST", f"/{WEB_TOKEN_TABLE}", json=payload)
        if ok:
            created = data[0] if isinstance(data, list) and data else data
            return {
                "ok": True,
                "token": token_plain,
                "token_hash": token_hash,
                "expires_at": expires_at,
                "token_row_id": (created or {}).get("id"),
                "accounts_id": accounts_id,
            }, None

        attempts.append(
            {"try": n, "status": dbg.get("status"), "root_cause": dbg.get("error_body") or data, "supabase": dbg}
        )

        if _looks_like_fk_violation(dbg):
            break

        if _looks_like_unique_violation(dbg):
            if TOKEN_INSERT_RETRY_SLEEP_MS > 0:
                time.sleep(TOKEN_INSERT_RETRY_SLEEP_MS / 1000.0)
            continue

        break

    return None, _fail(stage="token_insert", error="web_token_insert_failed", root_cause="insert_failed", extra={"attempts": attempts})


# -------------------- OTP Verify -> Token Issue --------------------

def verify_web_otp_and_issue_token(*, contact: str, otp: str, purpose: str) -> Dict[str, Any]:
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

    if REVOKE_OLD_TOKENS_ON_LOGIN:
        try:
            _revoke_all_tokens_for_account(str(acct["id"]))
        except Exception:
            pass

    token_res, token_err = _insert_web_token(acct)
    if token_err:
        return {"ok": False, **token_err}

    warnings = acct.get("_persist_warnings") or {}

    # IMPORTANT:
    # - return account_id as CANONICAL accounts.account_id if present, else fallback to accounts.id
    canonical_account_id = str((acct.get("account_id") or acct.get("id") or "")).strip()

    return {
        "ok": True,
        "account_id": canonical_account_id,
        "token": str(token_res["token"]),
        "expires_at": str(token_res["expires_at"]),
        "debug": {
            "otp_id": otp_row.get("id"),
            "tables": {"otp_table": WEB_OTP_TABLE, "token_table": WEB_TOKEN_TABLE, "accounts_table": ACCOUNTS_TABLE},
            "account_row": {
                "id": acct.get("id"),
                "account_id": acct.get("account_id"),
                "provider": acct.get("provider"),
                "provider_user_id": acct.get("provider_user_id"),
                "email": acct.get("email") or contact,
            },
            "token_insert": {
                "token_row_id": token_res.get("token_row_id"),
                "accounts_id": token_res.get("accounts_id"),
            },
            "persist_warnings": warnings or {"ok": True},
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

    # Some projects have no foreign-table embed relationship configured.
    # We still try embed, but we also work without it.
    params = {
        "select": "id,account_id,expires_at,revoked,last_seen_at,accounts(id,account_id,email,provider,provider_user_id)",
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

    # Canonical: accounts.account_id if present, else accounts.id, else token row account_id
    canonical_account_id: Optional[str] = None
    embedded = row.get("accounts")
    if isinstance(embedded, list) and embedded:
        embedded = embedded[0]

    if isinstance(embedded, dict):
        if embedded.get("account_id"):
            canonical_account_id = str(embedded.get("account_id"))
        elif embedded.get("id"):
            canonical_account_id = str(embedded.get("id"))

    if not canonical_account_id:
        # token row account_id points to accounts.id, but we accept it as fallback
        canonical_account_id = str(row.get("account_id")) if row.get("account_id") else None

    try:
        _sb_request("PATCH", f"/{WEB_TOKEN_TABLE}?id=eq.{row.get('id')}", json={"last_seen_at": _now_utc().isoformat()})
    except Exception:
        pass

    return canonical_account_id, {"ok": True, "debug": {"supabase": sb_dbg}}


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

    ok, data, sb_dbg = _sb_request("PATCH", f"/{WEB_TOKEN_TABLE}?token_hash=eq.{token_hash}", json={"revoked": True})
    if not ok:
        return _fail(stage="logout", error="logout_failed", root_cause=sb_dbg.get("error_body") or data, debug=sb_dbg, extra=src_dbg)

    return {"ok": True, "logged_out": True, **src_dbg}
