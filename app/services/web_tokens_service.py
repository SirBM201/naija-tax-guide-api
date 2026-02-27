# app/services/web_tokens_service.py
from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _split_peppers(v: str) -> List[str]:
    # Allow "pep1,pep2,pep3" for rotation / rollback
    out: List[str] = []
    for part in (v or "").split(","):
        p = part.strip()
        if p:
            out.append(p)
    return out


def _get_web_token_peppers() -> List[str]:
    """
    Pepper list for verifying tokens.
    First pepper is used to MINT new tokens.
    Others are accepted to VERIFY existing tokens (rotation support).
    """
    # Prefer explicit WEB_TOKEN_PEPPERS for rotation
    peppers = _split_peppers(os.getenv("WEB_TOKEN_PEPPERS", ""))

    # Backwards compat / simple setup:
    if not peppers:
        p = (os.getenv("WEB_TOKEN_PEPPER") or "").strip()
        if p:
            peppers = [p]

    # If still empty, try legacy names (avoid lockout)
    if not peppers:
        legacy = (os.getenv("TOKEN_HASH_PEPPER") or os.getenv("AUTH_TOKEN_PEPPER") or "").strip()
        if legacy:
            peppers = [legacy]

    return peppers


def _hash_token_plain(token_plain: str, pepper: str) -> str:
    # Deterministic, stable: sha256(f"{pepper}:{token_plain}")
    s = f"{pepper}:{token_plain}".encode("utf-8")
    return hashlib.sha256(s).hexdigest()


@dataclass(frozen=True)
class WebTokenRow:
    id: str
    account_id: str
    token_hash: str
    created_at: Optional[str]
    expires_at: Optional[str]
    revoked: bool


class WebTokensStore:
    """
    Minimal Supabase REST wrapper for table web_tokens.
    Uses service role key.
    """

    def __init__(self) -> None:
        self.supabase_url = (os.getenv("SUPABASE_URL") or "").strip()
        self.service_key = (os.getenv("SUPABASE_SERVICE_ROLE_KEY") or "").strip()

        self.table = (os.getenv("WEB_TOKEN_TABLE") or "web_tokens").strip()
        self.col_token_hash = (os.getenv("WEB_TOKEN_COL_TOKEN") or "token_hash").strip()
        self.col_account_id = (os.getenv("WEB_TOKEN_COL_ACCOUNT_ID") or "account_id").strip()
        self.col_expires_at = (os.getenv("WEB_TOKEN_COL_EXPIRES_AT") or "expires_at").strip()
        # your DB currently uses boolean 'revoked' (per screenshot)
        self.col_revoked = (os.getenv("WEB_TOKEN_COL_REVOKED") or "revoked").strip()

        if not self.supabase_url or not self.service_key:
            raise RuntimeError("SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY is missing")

    def _headers(self) -> Dict[str, str]:
        return {
            "apikey": self.service_key,
            "Authorization": f"Bearer {self.service_key}",
            "Content-Type": "application/json",
        }

    def find_by_hash(self, token_hash: str) -> Optional[WebTokenRow]:
        url = f"{self.supabase_url}/rest/v1/{self.table}"
        params = {
            "select": "*",
            self.col_token_hash: f"eq.{token_hash}",
            "limit": "1",
        }
        r = httpx.get(url, headers=self._headers(), params=params, timeout=15)
        r.raise_for_status()
        rows = r.json() or []
        if not rows:
            return None
        row = rows[0]
        return WebTokenRow(
            id=str(row.get("id")),
            account_id=str(row.get(self.col_account_id)),
            token_hash=str(row.get(self.col_token_hash)),
            created_at=row.get("created_at"),
            expires_at=row.get(self.col_expires_at),
            revoked=bool(row.get(self.col_revoked, False)),
        )

    def insert_token(self, account_id: str, token_hash: str, expires_at_iso: str) -> Dict[str, Any]:
        url = f"{self.supabase_url}/rest/v1/{self.table}"
        payload = {
            self.col_account_id: account_id,
            self.col_token_hash: token_hash,
            self.col_expires_at: expires_at_iso,
            self.col_revoked: False,
        }
        r = httpx.post(url, headers={**self._headers(), "Prefer": "return=representation"}, json=payload, timeout=15)
        r.raise_for_status()
        rows = r.json() or []
        return rows[0] if rows else {}

    def revoke_token(self, token_hash: str) -> None:
        url = f"{self.supabase_url}/rest/v1/{self.table}"
        params = {self.col_token_hash: f"eq.{token_hash}"}
        payload = {self.col_revoked: True}
        r = httpx.patch(url, headers=self._headers(), params=params, json=payload, timeout=15)
        r.raise_for_status()


def mint_web_token(account_id: str) -> Tuple[str, str]:
    """
    Returns (token_plain, token_hash).
    IMPORTANT:
      - token_plain is what you store in cookie / send to frontend
      - token_hash is what you store in DB (web_tokens.token_hash)
    """
    peppers = _get_web_token_peppers()
    if not peppers:
        raise RuntimeError("WEB_TOKEN_PEPPER is missing (or WEB_TOKEN_PEPPERS empty).")

    token_plain = secrets.token_urlsafe(32)  # 43-ish chars
    token_hash = _hash_token_plain(token_plain, peppers[0])
    return token_plain, token_hash


def get_web_session_ttl_days() -> int:
    v = (os.getenv("WEB_SESSION_TTL_DAYS") or "").strip()
    if v.isdigit():
        d = int(v)
        return max(1, min(d, 365))
    # default 30 days
    return 30


def verify_web_token_plain(token_plain: str) -> Tuple[Optional[WebTokenRow], Optional[str]]:
    """
    Verify cookie/bearer plaintext token.
    Returns (row, matched_pepper).
    """
    token_plain = (token_plain or "").strip()
    if not token_plain:
        return None, None

    peppers = _get_web_token_peppers()
    if not peppers:
        return None, None

    store = WebTokensStore()
    for pepper in peppers:
        token_hash = _hash_token_plain(token_plain, pepper)
        row = store.find_by_hash(token_hash)
        if row:
            return row, pepper

    return None, None


def parse_iso_dt(v: Any) -> Optional[datetime]:
    if not v:
        return None
    try:
        # expects something like "2026-03-29 08:45:01.727909+00" or ISO
        s = str(v).replace(" ", "T")
        # Ensure timezone
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def token_is_expired(row: WebTokenRow) -> bool:
    exp = parse_iso_dt(row.expires_at)
    if not exp:
        return False
    return exp <= _utcnow()
