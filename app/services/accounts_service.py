from __future__ import annotations

from typing import Optional, Dict, Any, Tuple, List
from datetime import datetime, timezone
import uuid
import os

from app.core.supabase_client import supabase


# ---------------------------------------------------------
# Common helpers
# ---------------------------------------------------------
def _sb():
    return supabase() if callable(supabase) else supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now_utc().isoformat()


def _clip(s: str, n: int = 260) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[:n] + "…"


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _debug_enabled() -> bool:
    return _truthy(os.getenv("ACCOUNTS_DEBUG", "0")) or _truthy(os.getenv("AUTH_DEBUG", "0"))


def _dbg(msg: str) -> None:
    if _debug_enabled():
        print(msg, flush=True)


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except Exception:
        return False


def _has_column(table: str, col: str) -> bool:
    try:
        _sb().table(table).select(col).limit(1).execute()
        return True
    except Exception:
        return False


def _safe_debug_meta() -> Dict[str, Any]:
    if not _debug_enabled():
        return {}
    return {"tables": {"accounts": "accounts"}, "env": (os.getenv("ENV", "prod") or "prod").lower()}


def _select_cols_existing(table: str, cols: List[str]) -> str:
    existing: List[str] = []
    for c in cols:
        if _has_column(table, c):
            existing.append(c)
    for must in ("id", "account_id", "provider", "provider_user_id"):
        if must not in existing and _has_column(table, must):
            existing.append(must)
    return ",".join(existing) if existing else "*"


# ---------------------------------------------------------
# Provider normalization
# ---------------------------------------------------------
ALLOWED_PROVIDERS = {"wa", "tg", "msgr", "ig", "email", "web"}

PROVIDER_ALIASES = {
    "wa": "wa",
    "whatsapp": "wa",
    "waba": "wa",
    "tg": "tg",
    "telegram": "tg",
    "msgr": "msgr",
    "messenger": "msgr",
    "facebook_messenger": "msgr",
    "fb_messenger": "msgr",
    "facebook messenger": "msgr",
    "ig": "ig",
    "instagram": "ig",
    "instagram_dm": "ig",
    "email": "email",
    "mail": "email",
    "web": "web",
    "website": "web",
}


def _norm_provider(provider: str) -> str:
    p = (provider or "").strip().lower()
    return PROVIDER_ALIASES.get(p, p)


def _validate_provider_and_id(provider: str, provider_user_id: str) -> Optional[str]:
    provider = _norm_provider(provider)
    if provider not in ALLOWED_PROVIDERS:
        return "provider must be one of: wa, tg, msgr, ig, email, web"
    provider_user_id = (provider_user_id or "").strip()
    if not provider_user_id:
        return "provider_user_id required"
    if provider == "email":
        v = provider_user_id.strip().lower()
        if "@" not in v or "." not in v:
            return "provider_user_id must be a valid email address for provider=email"
    return None


# ---------------------------------------------------------
# Canonical account_id extraction + auto-repair
# ---------------------------------------------------------
def _extract_account_id(row: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    if not isinstance(row, dict):
        return None, None
    account_id = str(row.get("account_id") or "").strip() or None
    row_id = str(row.get("id") or "").strip() or None
    return account_id, row_id


def _repair_account_id_if_needed(row: Dict[str, Any]) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    account_id, row_id = _extract_account_id(row)
    if account_id:
        return account_id, None

    if not row_id:
        return None, {
            "ok": False,
            "error": "account_id_missing",
            "root_cause": "accounts row missing both account_id and id",
            "fix": "Ensure accounts.id default uuid exists and account_id is present.",
            "debug": _safe_debug_meta(),
        }

    try:
        _sb().table("accounts").update({"account_id": row_id}).eq("id", row_id).execute()
        return row_id, None
    except Exception as e:
        return None, {
            "ok": False,
            "error": "account_id_repair_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": (
                "Run SQL as postgres:\n"
                "  update public.accounts set account_id = id where account_id is null;\n"
                "  create unique index if not exists uq_accounts_account_id on public.accounts(account_id);\n"
                "Also ensure your API uses Supabase SERVICE_ROLE key for updates."
            ),
            "details": {"row_id": row_id},
            "debug": _safe_debug_meta(),
        }


# ---------------------------------------------------------
# Low-level row helpers
# ---------------------------------------------------------
def _find_account_row(provider: str, provider_user_id: str, select_cols: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    try:
        res = (
            _sb()
            .table("accounts")
            .select(select_cols)
            .eq("provider", provider)
            .eq("provider_user_id", provider_user_id)
            .limit(1)
            .execute()
        )
    except Exception as e:
        return None, {
            "ok": False,
            "error": "db_error",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check accounts table access and schema.",
            "details": {"provider": provider, "provider_user_id": provider_user_id, "select": select_cols},
            "debug": _safe_debug_meta(),
        }

    row = (getattr(res, "data", None) or [None])[0] or None
    return row, None


def _insert_account_row(payload: Dict[str, Any], select_cols: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    try:
        res = _sb().table("accounts").insert(payload).select(select_cols).execute()
    except Exception as e:
        return None, {
            "ok": False,
            "error": "db_error",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check accounts insert permissions and required columns.",
            "details": {"payload_keys": sorted(list(payload.keys())), "select": select_cols},
            "debug": _safe_debug_meta(),
        }

    row = (getattr(res, "data", None) or [None])[0] or None
    if not row:
        return None, {
            "ok": False,
            "error": "db_error",
            "root_cause": "insert returned no row",
            "fix": "Ensure Supabase returns representation rows.",
            "debug": _safe_debug_meta(),
        }
    return row, None


def _update_account_row(row_id: str, patch: Dict[str, Any], select_cols: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    try:
        res = _sb().table("accounts").update(patch).eq("id", row_id).select(select_cols).execute()
    except Exception as e:
        return None, {
            "ok": False,
            "error": "db_error",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check accounts update permissions and row constraints.",
            "details": {"row_id": row_id, "patch_keys": sorted(list(patch.keys())), "select": select_cols},
            "debug": _safe_debug_meta(),
        }

    row = (getattr(res, "data", None) or [None])[0] or None
    if not row:
        return None, {
            "ok": False,
            "error": "db_error",
            "root_cause": "update returned no row",
            "fix": "Ensure the target row exists and Supabase returns representation rows.",
            "details": {"row_id": row_id},
            "debug": _safe_debug_meta(),
        }
    return row, None


# ---------------------------------------------------------
# Public API
# ---------------------------------------------------------
def upsert_account(
    *,
    provider: str,
    provider_user_id: str,
    display_name: Optional[str] = None,
    phone: Optional[str] = None,
) -> Dict[str, Any]:
    provider = _norm_provider(provider)
    provider_user_id = (provider_user_id or "").strip()

    err = _validate_provider_and_id(provider, provider_user_id)
    if err:
        return {"ok": False, "error": err}

    select_cols = _select_cols_existing(
        "accounts",
        ["id", "account_id", "provider", "provider_user_id", "auth_user_id", "display_name", "phone", "phone_e164", "updated_at", "created_at"],
    )

    existing, existing_err = _find_account_row(provider, provider_user_id, select_cols)
    if existing_err:
        return existing_err

    payload: Dict[str, Any] = {
        "provider": provider,
        "provider_user_id": provider_user_id,
        "updated_at": _now_iso(),
    }
    if display_name is not None and _has_column("accounts", "display_name"):
        payload["display_name"] = display_name
    if phone is not None:
        if _has_column("accounts", "phone"):
            payload["phone"] = phone
        if _has_column("accounts", "phone_e164"):
            payload["phone_e164"] = phone

    if existing and existing.get("id"):
        row, row_err = _update_account_row(str(existing["id"]), payload, select_cols)
    else:
        insert_payload: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "account_id": None,
            "created_at": _now_iso(),
            **payload,
        }
        row, row_err = _insert_account_row(insert_payload, select_cols)

    if row_err:
        return row_err

    account_id, err_obj = _repair_account_id_if_needed(row)
    if err_obj:
        return err_obj

    return {"ok": True, "account_id": account_id, "account": {**row, "account_id": account_id}}


def lookup_account(*, provider: str, provider_user_id: str) -> Dict[str, Any]:
    provider = _norm_provider(provider)
    provider_user_id = (provider_user_id or "").strip()

    err = _validate_provider_and_id(provider, provider_user_id)
    if err:
        return {"ok": False, "error": err}

    select_cols = _select_cols_existing(
        "accounts",
        ["id", "account_id", "provider", "provider_user_id", "auth_user_id", "display_name", "phone", "phone_e164", "updated_at", "created_at"],
    )

    row, row_err = _find_account_row(provider, provider_user_id, select_cols)
    if row_err:
        return row_err

    if not row:
        return {"ok": True, "found": False, "linked": False, "auth_user_id": None, "account_id": None, "account": None}

    account_id, err_obj = _repair_account_id_if_needed(row)
    if err_obj:
        return err_obj

    auth_user_id = row.get("auth_user_id") if isinstance(row, dict) else None
    return {
        "ok": True,
        "found": True,
        "linked": bool(auth_user_id),
        "auth_user_id": auth_user_id,
        "account_id": account_id,
        "account": {**row, "account_id": account_id},
    }


def upsert_account_link(
    *,
    provider: str,
    provider_user_id: str,
    auth_user_id: str,
    display_name: Optional[str] = None,
    phone: Optional[str] = None,
) -> Dict[str, Any]:
    provider = _norm_provider(provider)
    provider_user_id = (provider_user_id or "").strip()
    auth_user_id = (auth_user_id or "").strip()

    err = _validate_provider_and_id(provider, provider_user_id)
    if err:
        return {"ok": False, "error": err}
    if not auth_user_id:
        return {"ok": False, "error": "auth_user_id required"}
    if not _is_uuid(auth_user_id):
        return {"ok": False, "error": "auth_user_id must be a valid uuid"}

    select_cols = _select_cols_existing(
        "accounts",
        ["id", "account_id", "provider", "provider_user_id", "auth_user_id", "display_name", "phone", "phone_e164", "updated_at", "created_at"],
    )

    existing, existing_err = _find_account_row(provider, provider_user_id, select_cols)
    if existing_err:
        return existing_err

    if existing:
        old = str(existing.get("auth_user_id") or "").strip()
        if old and old != auth_user_id:
            return {"ok": False, "error": "This channel is already linked to another account.", "reason": "channel_already_linked"}

        patch: Dict[str, Any] = {
            "auth_user_id": auth_user_id,
            "updated_at": _now_iso(),
        }
        if display_name is not None and _has_column("accounts", "display_name"):
            patch["display_name"] = display_name
        if phone is not None:
            if _has_column("accounts", "phone"):
                patch["phone"] = phone
            if _has_column("accounts", "phone_e164"):
                patch["phone_e164"] = phone

        row, row_err = _update_account_row(str(existing.get("id")), patch, select_cols)
        if row_err:
            return row_err
    else:
        insert_payload: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "account_id": None,
            "provider": provider,
            "provider_user_id": provider_user_id,
            "auth_user_id": auth_user_id,
            "created_at": _now_iso(),
            "updated_at": _now_iso(),
        }
        if display_name is not None and _has_column("accounts", "display_name"):
            insert_payload["display_name"] = display_name
        if phone is not None:
            if _has_column("accounts", "phone"):
                insert_payload["phone"] = phone
            if _has_column("accounts", "phone_e164"):
                insert_payload["phone_e164"] = phone

        row, row_err = _insert_account_row(insert_payload, select_cols)
        if row_err:
            return row_err

    account_id, err_obj = _repair_account_id_if_needed(row)
    if err_obj:
        return err_obj

    return {"ok": True, "account_id": account_id, "account": {**row, "account_id": account_id}}


def ensure_account_id(
    *,
    provider: str,
    provider_user_id: str,
    phone_e164: Optional[str] = None,
    phone: Optional[str] = None,
    display_name: Optional[str] = None,
    contact: Optional[str] = None,
) -> Dict[str, Any]:
    provider = _norm_provider(provider)
    provider_user_id = (provider_user_id or "").strip()

    err = _validate_provider_and_id(provider, provider_user_id)
    if err:
        return {"ok": False, "error": err}

    phone_value = phone_e164 or phone or contact or None
    return upsert_account(provider=provider, provider_user_id=provider_user_id, display_name=display_name, phone=phone_value)


# ---------------------------------------------------------
# Optional: plan helper
# ---------------------------------------------------------
def _plan_from_subscriptions_table(auth_user_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        res = (
            _sb()
            .table("subscriptions")
            .select("user_id,plan,status,start_at,end_at,updated_at,id")
            .eq("user_id", auth_user_id)
            .order("updated_at", desc=True)
            .limit(1)
            .execute()
        )
    except Exception as e:
        return None, f"DB error: {_clip(str(e))}"

    row = (getattr(res, "data", None) or [None])[0]
    if not row:
        return None, None
    return row, None
