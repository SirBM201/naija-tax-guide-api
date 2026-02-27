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

WEB_AUTH_COOKIE_NAME = (os.getenv("WEB_AUTH_COOKIE_NAME", "ntg_web_token").strip() or "ntg_web_token")

TOKEN_INSERT_MAX_RETRIES = int(os.getenv("WEB_TOKEN_INSERT_MAX_RETRIES", "5") or "5")
TOKEN_INSERT_RETRY_SLEEP_MS = int(os.getenv("WEB_TOKEN_INSERT_RETRY_SLEEP_MS", "50") or "50")

REVOKE_OLD_TOKENS_ON_LOGIN = str(os.getenv("WEB_REVOKE_OLD_TOKENS_ON_LOGIN", "1")).strip().lower() in {
    "1", "true", "yes", "y", "on"
}


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _require_env(*names: str) -> str:
    """
    Return first non-empty env value from names.
    Raise if none present.
    """
    for n in names:
        v = (os.getenv(n) or "").strip()
        if v:
            return v
    raise RuntimeError(f"Missing required env var. Provide one of: {', '.join(names)}")


def _otp_pepper() -> str:
    # Prefer specific peppers you showed in screenshots
    # (OTP_HASH_PEPPER is commonly used name; WEB_OTP_PEPPER is also ok)
    return _require_env("WEB_OTP_PEPPER", "OTP_HASH_PEPPER")


def _token_pepper() -> str:
    # Prefer specific token pepper you showed
    return _require_env("WEB_TOKEN_PEPPER")


def _otp_ttl_minutes() -> int:
    return int(os.getenv("WEB_OTP_TTL_MINUTES", "10") or "10")


def _token_ttl_days() -> int:
    return int(os.getenv("WEB_TOKEN_TTL_DAYS", "30") or "30")


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


def _hash_otp(otp: str) -> str:
    # IMPORTANT: uses OTP pepper
    return _sha256_hex(f"otp:{otp}:{_otp_pepper()}")


def _hash_token(token: str) -> str:
    # IMPORTANT: uses TOKEN pepper
    return _sha256_hex(f"tok:{token}:{_token_pepper()}")


def _looks_like_fk_violation(dbg: Dict[str, Any]) -> bool:
    body = (dbg.get("error_body") or "")
    return ("23503" in body) or ("foreign key" in body.lower()) or ("violates foreign key" in body.lower())


def _looks_like_unique_violation(dbg: Dict[str, Any]) -> bool:
    body = (dbg.get("error_body") or "")
    return ("23505" in body) or (dbg.get("status") == 409) or ("duplicate key" in body.lower()) or ("unique" in body.lower())


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
            "received": {"device_id": device_id, "ip": ip, "user_agent_present": bool(user_agent)},
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
    ok, data, dbg = _sb_request(
        "PATCH",
        f"/web_otps?id=eq.{otp_id}",
        json={"used": True, "used_at": _now_utc().isoformat()},
    )
    if ok:
        return {"ok": True}
    return {"ok": False, "root_cause": dbg.get("error_body") or data, "debug": dbg}


def _get_or_create_web_account(contact: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    params = {
        "select": "id,account_id,provider,provider_user_id,created_at",
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

    row = {"provider": "web", "provider_user_id": contact}
    ok, data, dbg = _sb_request("POST", "/accounts", json=row)
    if not ok:
        return None, {"error": "account_create_failed", "root_cause": dbg.get("error_body") or data, "debug": dbg}

    created = data[0] if isinstance(data, list) and data else data
    return created, None


def _revoke_all_tokens_for_account(accounts_id: str) -> None:
    _sb_request("PATCH", f"/web_tokens?account_id=eq.{accounts_id}", json={"revoked": True})


def _insert_web_token(account_row: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    DB constraint:
      web_tokens.account_id REFERENCES accounts(id)
    So ALWAYS insert accounts.id into web_tokens.account_id.
    """
    accounts_id = str(account_row["id"])
    expires_at = (_now_utc() + timedelta(days=_token_ttl_days())).isoformat()

    attempts: List[Dict[str, Any]] = []

    for n in range(1, TOKEN_INSERT_MAX_RETRIES + 1):
        token_plain = secrets.token_urlsafe(48)
        token_hash = _hash_token(token_plain)

        payload = {
            "token_hash": token_hash,
            "account_id": accounts_id,
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
                "token_row_id": (created or {}).get("id"),
                "accounts_id": accounts_id,
            }, None

        attempts.append({"try": n, "status": dbg.get("status"), "root_cause": dbg.get("error_body") or data, "supabase": dbg})

        if _looks_like_fk_violation(dbg):
            break

        if _looks_like_unique_violation(dbg):
            if TOKEN_INSERT_RETRY_SLEEP_MS > 0:
                time.sleep(TOKEN_INSERT_RETRY_SLEEP_MS / 1000.0)
            continue

        break

    return None, {"error": "web_token_insert_failed", "root_cause": "insert_failed", "attempts": attempts}


def verify_web_otp_and_issue_token(*, contact: str, otp: str, purpose: str) -> Dict[str, Any]:
    contact = (contact or "").strip().lower()
    purpose = (purpose or "web_login").strip().lower()
    otp = (otp or "").strip()

    if not contact or not otp:
        return {"ok": False, "error": "contact_and_otp_required"}

    otp_row, otp_dbg = _find_latest_otp(contact, purpose)
    if not otp_row:
        return {"ok": False, "error": "otp_not_found", **otp_dbg}

    if otp_row.get("used") is True:
        return {"ok": False, "error": "otp_already_used", "otp_id": otp_row.get("id")}

    try:
        exp = str(otp_row["expires_at"])
        exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        if _now_utc() >= exp_dt:
            return {"ok": False, "error": "otp_expired", "expires_at": exp, "otp_id": otp_row.get("id")}
    except Exception as e:
        return {"ok": False, "error": "otp_expiry_parse_failed", "root_cause": repr(e), "otp_row": otp_row}

    if _hash_otp(otp) != (otp_row.get("code_hash") or ""):
        return {"ok": False, "error": "otp_invalid", "otp_id": otp_row.get("id")}

    used_res = _mark_otp_used(str(otp_row["id"]))
    if used_res and not used_res.get("ok"):
        return {"ok": False, "error": "otp_mark_used_failed", "root_cause": used_res.get("root_cause"), "debug": used_res.get("debug")}

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
        return {"ok": False, "error": "token_issue_failed", **token_err}

    public_account_id = acct.get("account_id") or acct.get("id")

    return {
        "ok": True,
        "account_id": str(public_account_id),
        "token": str(token_res["token"]),
        "expires_at": str(token_res["expires_at"]),
        "debug": {
            "otp_id": otp_row.get("id"),
            "account_row": {"id": acct.get("id"), "account_id": acct.get("account_id")},
            "token_insert": {"token_row_id": token_res.get("token_row_id"), "accounts_id": token_res.get("accounts_id")},
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
    token, src_dbg = _extract_token_from_request(req)
    if not token:
        return None, {"ok": False, "error": "missing_token", **src_dbg}

    token_hash = _hash_token(token)

    params = {
        "select": "id,account_id,expires_at,revoked,last_seen_at,accounts(id,account_id)",
        "token_hash": f"eq.{token_hash}",
        "limit": "1",
    }
    ok, data, sb_dbg = _sb_request("GET", "/web_tokens", params=params)
    if not ok:
        return None, {"ok": False, "error": "token_lookup_failed", "root_cause": sb_dbg.get("error_body") or data, "debug": sb_dbg, **src_dbg}

    rows = data if isinstance(data, list) else []
    if not rows:
        return None, {"ok": False, "error": "invalid_token", **src_dbg}

    row = rows[0]
    if row.get("revoked") is True:
        return None, {"ok": False, "error": "token_revoked", **src_dbg}

    try:
        exp_dt = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
        if _now_utc() >= exp_dt:
            return None, {"ok": False, "error": "token_expired", "expires_at": row.get("expires_at"), **src_dbg}
    except Exception as e:
        return None, {"ok": False, "error": "token_expiry_parse_failed", "root_cause": repr(e), "token_row": row, **src_dbg}

    public_account_id: Optional[str] = None
    embedded = row.get("accounts")
    if isinstance(embedded, list) and embedded:
        embedded = embedded[0]

    if isinstance(embedded, dict):
        if embedded.get("account_id"):
            public_account_id = str(embedded.get("account_id"))
        elif embedded.get("id"):
            public_account_id = str(embedded.get("id"))

    if not public_account_id:
        public_account_id = str(row.get("account_id")) if row.get("account_id") else None

    try:
        _sb_request("PATCH", f"/web_tokens?id=eq.{row.get('id')}", json={"last_seen_at": _now_utc().isoformat()})
    except Exception:
        pass

    return public_account_id, {"ok": True, **src_dbg, "debug": {"supabase": sb_dbg}}


def logout_web_session(req: Request) -> Dict[str, Any]:
    token, src_dbg = _extract_token_from_request(req)
    if not token:
        return {"ok": True, "logged_out": False, "reason": "no_token", **src_dbg}

    token_hash = _hash_token(token)

    ok, data, sb_dbg = _sb_request("PATCH", f"/web_tokens?token_hash=eq.{token_hash}", json={"revoked": True})
    if not ok:
        return {"ok": False, "error": "logout_failed", "root_cause": sb_dbg.get("error_body") or data, "debug": sb_dbg, **src_dbg}

    return {"ok": True, "logged_out": True, **src_dbg}
