from __future__ import annotations

import os
import random
import string
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

from app.core.supabase_client import supabase


# =========================================================
# INTERNAL HELPERS
# =========================================================

def _sb():
    return supabase() if callable(supabase) else supabase


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        raw = str(value).strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        return datetime.fromisoformat(raw)
    except Exception:
        return None


def _clean_code(value: str | None) -> str:
    return "".join(ch for ch in str(value or "").strip().upper() if ch.isalnum())


def _frontend_base_url() -> str:
    return (
        os.getenv("FRONTEND_APP_URL")
        or os.getenv("NEXT_PUBLIC_APP_URL")
        or os.getenv("APP_PUBLIC_URL")
        or ""
    ).rstrip("/")


def _choice(chars: str, n: int) -> str:
    return "".join(random.choice(chars) for _ in range(n))


def _response_data(resp: Any) -> List[Dict[str, Any]]:
    if resp is None:
        return []
    data = getattr(resp, "data", None)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    return []


def _first(resp: Any) -> Optional[Dict[str, Any]]:
    rows = _response_data(resp)
    return rows[0] if rows else None


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _to_decimal(value: Any, default: Decimal = Decimal("0")) -> Decimal:
    try:
        if value is None:
            return default
        return Decimal(str(value))
    except Exception:
        return default


# =========================================================
# ENV / PROGRAM CONFIG
# =========================================================

def _program_enabled() -> bool:
    return str(os.getenv("REFERRAL_PROGRAM_ENABLED") or "1").strip().lower() in {
        "1", "true", "yes", "y", "on"
    }


def _referral_prefix() -> str:
    code = _clean_code(os.getenv("REFERRAL_CODE_PREFIX") or "NTG")
    return code or "NTG"


def _referral_code_length() -> int:
    raw = str(os.getenv("REFERRAL_CODE_RANDOM_LENGTH") or "6").strip()
    try:
        n = int(raw)
        return n if n >= 4 else 6
    except Exception:
        return 6


def _reward_currency() -> str:
    return str(os.getenv("REFERRAL_REWARD_CURRENCY") or "NGN").strip().upper()


def _max_levels() -> int:
    raw = str(os.getenv("REFERRAL_MAX_LEVELS") or "2").strip()
    try:
        n = int(raw)
        if n < 1:
            return 1
        if n > 2:
            return 2
        return n
    except Exception:
        return 2


def _level1_bonus() -> Decimal:
    return _to_decimal(os.getenv("REFERRAL_LEVEL1_BONUS") or "500", Decimal("500"))


def _level2_bonus() -> Decimal:
    return _to_decimal(os.getenv("REFERRAL_LEVEL2_BONUS") or "200", Decimal("200"))


def _hold_days() -> int:
    raw = str(os.getenv("REFERRAL_REWARD_HOLD_DAYS") or "14").strip()
    try:
        n = int(raw)
        return n if n >= 0 else 14
    except Exception:
        return 14


def _initial_reward_status() -> str:
    return str(os.getenv("REFERRAL_REWARD_INITIAL_STATUS") or "pending").strip().lower()


def _mature_reward_status() -> str:
    return str(os.getenv("REFERRAL_REWARD_MATURE_STATUS") or "approved").strip().lower()


def _completed_referral_status() -> str:
    return str(os.getenv("REFERRAL_COMPLETED_STATUS") or "rewarded").strip().lower()


def _prevent_self_referral() -> bool:
    return str(os.getenv("REFERRAL_PREVENT_SELF_REFERRAL") or "1").strip().lower() in {
        "1", "true", "yes", "y", "on"
    }


def _require_first_successful_payment() -> bool:
    return str(os.getenv("REFERRAL_REQUIRE_FIRST_SUCCESSFUL_PAYMENT") or "1").strip().lower() in {
        "1", "true", "yes", "y", "on"
    }


def _one_time_per_referred_user() -> bool:
    return str(os.getenv("REFERRAL_ONE_TIME_PER_REFERRED_USER") or "1").strip().lower() in {
        "1", "true", "yes", "y", "on"
    }


def _skip_if_existing_reward_found() -> bool:
    return str(os.getenv("REFERRAL_SKIP_IF_EXISTING_REWARD_FOUND") or "1").strip().lower() in {
        "1", "true", "yes", "y", "on"
    }


# =========================================================
# DATA CLASSES
# =========================================================

@dataclass
class ReferralBootstrapResult:
    account_id: str
    own_profile: Dict[str, Any]
    captured_referral: Optional[Dict[str, Any]]
    skipped_reason: Optional[str] = None


# =========================================================
# LOW-LEVEL READ HELPERS
# =========================================================

def get_referral_profile_by_account_id(account_id: str) -> Optional[Dict[str, Any]]:
    account_id = str(account_id or "").strip()
    if not account_id:
        return None

    resp = (
        _sb()
        .table("referral_profiles")
        .select("*")
        .eq("account_id", account_id)
        .limit(1)
        .execute()
    )
    return _first(resp)


def get_referral_profile_by_code(referral_code: str) -> Optional[Dict[str, Any]]:
    code = _clean_code(referral_code)
    if not code:
        return None

    resp = (
        _sb()
        .table("referral_profiles")
        .select("*")
        .eq("referral_code", code)
        .eq("is_active", True)
        .limit(1)
        .execute()
    )
    return _first(resp)


def get_referral_row_by_referred_account_id(referred_account_id: str) -> Optional[Dict[str, Any]]:
    referred_account_id = str(referred_account_id or "").strip()
    if not referred_account_id:
        return None

    resp = (
        _sb()
        .table("referrals")
        .select("*")
        .eq("referred_account_id", referred_account_id)
        .limit(1)
        .execute()
    )
    return _first(resp)


def get_referral_row_by_id(referral_id: str) -> Optional[Dict[str, Any]]:
    referral_id = str(referral_id or "").strip()
    if not referral_id:
        return None

    resp = (
        _sb()
        .table("referrals")
        .select("*")
        .eq("id", referral_id)
        .limit(1)
        .execute()
    )
    return _first(resp)


def get_reward_rows_for_referral(referral_id: str) -> List[Dict[str, Any]]:
    referral_id = str(referral_id or "").strip()
    if not referral_id:
        return []

    resp = (
        _sb()
        .table("referral_rewards")
        .select("*")
        .eq("referral_id", referral_id)
        .execute()
    )
    return _response_data(resp)


def get_reward_rows_for_account(account_id: str) -> List[Dict[str, Any]]:
    account_id = str(account_id or "").strip()
    if not account_id:
        return []

    resp = (
        _sb()
        .table("referral_rewards")
        .select("*")
        .eq("account_id", account_id)
        .execute()
    )
    return _response_data(resp)


def get_reward_rows_by_payment_reference(payment_reference: str) -> List[Dict[str, Any]]:
    payment_reference = str(payment_reference or "").strip()
    if not payment_reference:
        return []

    resp = (
        _sb()
        .table("referral_rewards")
        .select("*")
        .eq("payment_reference", payment_reference)
        .execute()
    )
    return _response_data(resp)


# =========================================================
# REFERRAL PROFILE CREATION
# =========================================================

def build_referral_link(referral_code: str) -> str:
    base = _frontend_base_url()
    code = _clean_code(referral_code)
    if not code:
        return ""
    if not base:
        return f"/signup?ref={code}"
    return f"{base}/signup?ref={code}"


def _generate_candidate_referral_code() -> str:
    prefix = _referral_prefix()
    length = _referral_code_length()
    suffix = _choice(string.ascii_uppercase + string.digits, length)
    return f"{prefix}{suffix}"


def generate_unique_referral_code(max_attempts: int = 50) -> str:
    for _ in range(max_attempts):
        candidate = _generate_candidate_referral_code()
        exists = get_referral_profile_by_code(candidate)
        if not exists:
            return candidate
    raise RuntimeError("Unable to generate a unique referral code after multiple attempts.")


def ensure_referral_profile(account_id: str) -> Dict[str, Any]:
    if not _program_enabled():
        raise RuntimeError("Referral program is disabled.")

    account_id = str(account_id or "").strip()
    if not account_id:
        raise ValueError("account_id is required")

    existing = get_referral_profile_by_account_id(account_id)
    if existing:
        return existing

    code = generate_unique_referral_code()
    link = build_referral_link(code)
    now_iso = _now_iso()

    payload = {
        "account_id": account_id,
        "referral_code": code,
        "referral_link": link,
        "is_active": True,
        "created_at": now_iso,
        "updated_at": now_iso,
    }

    resp = _sb().table("referral_profiles").insert(payload).execute()
    created = _first(resp)
    if created:
        return created

    again = get_referral_profile_by_account_id(account_id)
    if again:
        return again

    raise RuntimeError("Failed to create referral profile.")


# =========================================================
# REFERRAL CAPTURE / ACCOUNT BOOTSTRAP
# =========================================================

def create_pending_referral(
    *,
    referrer_account_id: str,
    referred_account_id: str,
    referral_code: str,
    source: str = "signup",
) -> Dict[str, Any]:
    if not _program_enabled():
        raise RuntimeError("Referral program is disabled.")

    referrer_account_id = str(referrer_account_id or "").strip()
    referred_account_id = str(referred_account_id or "").strip()
    referral_code = _clean_code(referral_code)
    source = str(source or "signup").strip()

    if not referrer_account_id:
        raise ValueError("referrer_account_id is required")
    if not referred_account_id:
        raise ValueError("referred_account_id is required")
    if not referral_code:
        raise ValueError("referral_code is required")

    if _prevent_self_referral() and referrer_account_id == referred_account_id:
        raise ValueError("Self-referral is not allowed")

    existing = get_referral_row_by_referred_account_id(referred_account_id)
    if existing:
        return existing

    now_iso = _now_iso()
    payload = {
        "referrer_account_id": referrer_account_id,
        "referred_account_id": referred_account_id,
        "referral_code": referral_code,
        "status": "pending",
        "source": source,
        "signup_at": now_iso,
        "created_at": now_iso,
        "updated_at": now_iso,
    }

    resp = _sb().table("referrals").insert(payload).execute()
    created = _first(resp)
    if created:
        return created

    again = get_referral_row_by_referred_account_id(referred_account_id)
    if again:
        return again

    raise RuntimeError("Failed to create pending referral row.")


def bootstrap_new_account_for_referrals(
    *,
    account_id: str,
    incoming_referral_code: str | None = None,
    source: str = "signup",
) -> ReferralBootstrapResult:
    account_id = str(account_id or "").strip()
    if not account_id:
        raise ValueError("account_id is required")

    own_profile = ensure_referral_profile(account_id)

    incoming_referral_code = _clean_code(incoming_referral_code)
    if not incoming_referral_code:
        return ReferralBootstrapResult(
            account_id=account_id,
            own_profile=own_profile,
            captured_referral=None,
            skipped_reason="no_incoming_referral_code",
        )

    referrer_profile = get_referral_profile_by_code(incoming_referral_code)
    if not referrer_profile:
        return ReferralBootstrapResult(
            account_id=account_id,
            own_profile=own_profile,
            captured_referral=None,
            skipped_reason="invalid_referral_code",
        )

    referrer_account_id = str(referrer_profile.get("account_id") or "").strip()
    if not referrer_account_id:
        return ReferralBootstrapResult(
            account_id=account_id,
            own_profile=own_profile,
            captured_referral=None,
            skipped_reason="invalid_referrer_profile",
        )

    if _prevent_self_referral() and referrer_account_id == account_id:
        return ReferralBootstrapResult(
            account_id=account_id,
            own_profile=own_profile,
            captured_referral=None,
            skipped_reason="self_referral_blocked",
        )

    captured = create_pending_referral(
        referrer_account_id=referrer_account_id,
        referred_account_id=account_id,
        referral_code=incoming_referral_code,
        source=source,
    )

    return ReferralBootstrapResult(
        account_id=account_id,
        own_profile=own_profile,
        captured_referral=captured,
        skipped_reason=None,
    )


# =========================================================
# REWARD LEDGER HELPERS
# =========================================================

def _reward_type_for_level(level: int) -> str:
    return f"cash_level_{level}"


def _reward_amount_for_level(level: int) -> Decimal:
    if level == 1:
        return _level1_bonus()
    if level == 2:
        return _level2_bonus()
    return Decimal("0")


def _existing_reward_for_referral_account_level(
    *,
    referral_id: str,
    account_id: str,
    level: int,
) -> Optional[Dict[str, Any]]:
    referral_id = str(referral_id or "").strip()
    account_id = str(account_id or "").strip()
    reward_type = _reward_type_for_level(level)

    if not referral_id or not account_id:
        return None

    resp = (
        _sb()
        .table("referral_rewards")
        .select("*")
        .eq("referral_id", referral_id)
        .eq("account_id", account_id)
        .eq("reward_type", reward_type)
        .limit(1)
        .execute()
    )
    return _first(resp)


def _create_reward_row(
    *,
    referral_id: str,
    beneficiary_account_id: str,
    level: int,
    payment_reference: str,
    plan_code: str | None,
) -> Dict[str, Any]:
    now_iso = _now_iso()
    amount = _reward_amount_for_level(level)
    if amount <= 0:
        raise ValueError(f"Invalid reward amount for level {level}")

    payload = {
        "referral_id": referral_id,
        "account_id": beneficiary_account_id,
        "reward_type": _reward_type_for_level(level),
        "reward_amount": str(amount),
        "currency": _reward_currency(),
        "status": _initial_reward_status(),
        "plan_code": plan_code,
        "payment_reference": payment_reference,
        "earned_at": now_iso,
        "created_at": now_iso,
        "updated_at": now_iso,
    }

    resp = _sb().table("referral_rewards").insert(payload).execute()
    row = _first(resp)
    if row:
        return row

    existing = _existing_reward_for_referral_account_level(
        referral_id=referral_id,
        account_id=beneficiary_account_id,
        level=level,
    )
    if existing:
        return existing

    raise RuntimeError("Failed to create referral reward row.")


def _find_level_chain_for_paid_user(paid_account_id: str) -> List[Dict[str, Any]]:
    """
    Returns up to 2 reward recipients for the paying referred user.

    Example:
      A refers B
      B refers C
      C pays

      level 1 => B
      level 2 => A
    """
    paid_account_id = str(paid_account_id or "").strip()
    if not paid_account_id:
        return []

    chain: List[Dict[str, Any]] = []
    max_levels = _max_levels()

    direct_referral = get_referral_row_by_referred_account_id(paid_account_id)
    if not direct_referral:
        return chain

    level1_account_id = str(direct_referral.get("referrer_account_id") or "").strip()
    if level1_account_id:
        chain.append(
            {
                "level": 1,
                "beneficiary_account_id": level1_account_id,
                "referral_row": direct_referral,
            }
        )

    if max_levels < 2 or not level1_account_id:
        return chain

    parent_referral = get_referral_row_by_referred_account_id(level1_account_id)
    if not parent_referral:
        return chain

    level2_account_id = str(parent_referral.get("referrer_account_id") or "").strip()
    if not level2_account_id:
        return chain

    if level2_account_id == paid_account_id:
        return chain

    chain.append(
        {
            "level": 2,
            "beneficiary_account_id": level2_account_id,
            "referral_row": direct_referral,
            "parent_referral_row": parent_referral,
        }
    )
    return chain


# =========================================================
# QUALIFICATION AFTER SUCCESSFUL PAYMENT
# =========================================================

def qualify_referral_after_successful_payment(
    *,
    paying_account_id: str,
    payment_reference: str,
    plan_code: str | None = None,
) -> Dict[str, Any]:
    """
    Called after a verified first successful paid subscription.

    Creates:
      - level 1 reward row for direct referrer (₦500)
      - level 2 reward row for indirect referrer (₦200), if available

    Rewards start as pending and mature later after hold_days.
    """
    if not _program_enabled():
        return {
            "ok": True,
            "qualified": False,
            "reason": "referral_program_disabled",
        }

    paying_account_id = str(paying_account_id or "").strip()
    payment_reference = str(payment_reference or "").strip()
    plan_code = str(plan_code or "").strip().lower() or None

    if not paying_account_id:
        raise ValueError("paying_account_id is required")
    if not payment_reference:
        raise ValueError("payment_reference is required")

    direct_referral = get_referral_row_by_referred_account_id(paying_account_id)
    if not direct_referral:
        return {
            "ok": True,
            "qualified": False,
            "reason": "no_referral_found",
        }

    direct_referral_id = str(direct_referral.get("id") or "").strip()

    if _skip_if_existing_reward_found():
        existing_payment_rewards = get_reward_rows_by_payment_reference(payment_reference)
        if existing_payment_rewards:
            return {
                "ok": True,
                "qualified": False,
                "reason": "payment_reference_already_rewarded",
                "reward_rows": existing_payment_rewards,
                "referral_id": direct_referral_id,
            }

    if _one_time_per_referred_user():
        existing_rewards = get_reward_rows_for_referral(direct_referral_id)
        if existing_rewards:
            return {
                "ok": True,
                "qualified": False,
                "reason": "referred_user_already_rewarded_once",
                "reward_rows": existing_rewards,
                "referral_id": direct_referral_id,
            }

    current_status = str(direct_referral.get("status") or "").strip().lower()
    if current_status in {"disqualified", "expired"}:
        return {
            "ok": True,
            "qualified": False,
            "reason": f"referral_status_{current_status}",
            "referral_id": direct_referral_id,
        }

    beneficiaries = _find_level_chain_for_paid_user(paying_account_id)
    if not beneficiaries:
        return {
            "ok": True,
            "qualified": False,
            "reason": "no_eligible_beneficiaries",
            "referral_id": direct_referral_id,
        }

    now_iso = _now_iso()

    # Mark the direct referral row as qualified before reward creation.
    _sb().table("referrals").update(
        {
            "status": "qualified",
            "qualified_at": now_iso,
            "updated_at": now_iso,
        }
    ).eq("id", direct_referral_id).execute()

    created_rewards: List[Dict[str, Any]] = []
    for item in beneficiaries:
        level = _safe_int(item.get("level"), 0)
        beneficiary_account_id = str(item.get("beneficiary_account_id") or "").strip()

        if not beneficiary_account_id or level not in {1, 2}:
            continue

        existing = _existing_reward_for_referral_account_level(
            referral_id=direct_referral_id,
            account_id=beneficiary_account_id,
            level=level,
        )
        if existing:
            created_rewards.append(existing)
            continue

        created = _create_reward_row(
            referral_id=direct_referral_id,
            beneficiary_account_id=beneficiary_account_id,
            level=level,
            payment_reference=payment_reference,
            plan_code=plan_code,
        )
        created_rewards.append(created)

    # Final direct referral status after reward creation.
    target_status = _completed_referral_status()
    if target_status in {"qualified", "rewarded"}:
        _sb().table("referrals").update(
            {
                "status": target_status,
                "updated_at": now_iso,
            }
        ).eq("id", direct_referral_id).execute()

    final_referral = get_referral_row_by_referred_account_id(paying_account_id)

    return {
        "ok": True,
        "qualified": bool(created_rewards),
        "reason": "reward_rows_created" if created_rewards else "no_reward_rows_created",
        "referral_id": direct_referral_id,
        "rewards": created_rewards,
        "referral": final_referral,
        "hold_days": _hold_days(),
        "initial_reward_status": _initial_reward_status(),
    }


# =========================================================
# HOLD / MATURITY LOGIC
# =========================================================

def is_reward_ready_to_mature(reward_row: Dict[str, Any], now_dt: Optional[datetime] = None) -> bool:
    now_dt = now_dt or _now()
    status = str(reward_row.get("status") or "").strip().lower()
    if status != _initial_reward_status():
        return False

    earned_at = _parse_dt(reward_row.get("earned_at")) or _parse_dt(reward_row.get("created_at"))
    if not earned_at:
        return False

    maturity_time = earned_at + timedelta(days=_hold_days())
    return now_dt >= maturity_time


def mature_pending_rewards(
    *,
    account_id: str | None = None,
    limit: int = 500,
) -> Dict[str, Any]:
    """
    Converts reward rows from pending -> approved after hold period.

    Call this:
    - from admin cron
    - before showing withdrawable balance
    - before generating payout batch
    """
    limit = max(1, min(_safe_int(limit, 500), 2000))
    q = (
        _sb()
        .table("referral_rewards")
        .select("*")
        .eq("status", _initial_reward_status())
        .order("created_at", desc=False)
        .limit(limit)
    )

    if account_id:
        q = q.eq("account_id", str(account_id).strip())

    resp = q.execute()
    rows = _response_data(resp)

    now_dt = _now()
    matured: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    for row in rows:
        if not is_reward_ready_to_mature(row, now_dt=now_dt):
            skipped.append(
                {
                    "reward_id": row.get("id"),
                    "reason": "hold_not_finished",
                }
            )
            continue

        reward_id = str(row.get("id") or "").strip()
        if not reward_id:
            continue

        update_resp = (
            _sb()
            .table("referral_rewards")
            .update(
                {
                    "status": _mature_reward_status(),
                    "approved_at": _now_iso(),
                    "updated_at": _now_iso(),
                }
            )
            .eq("id", reward_id)
            .execute()
        )
        updated = _first(update_resp)
        matured.append(updated or row)

    return {
        "ok": True,
        "checked": len(rows),
        "matured_count": len(matured),
        "skipped_count": len(skipped),
        "matured": matured,
        "skipped": skipped,
    }


# =========================================================
# DISQUALIFY / EXPIRE / REVERSE HELPERS
# =========================================================

def disqualify_referral(
    *,
    referred_account_id: str,
    reason: str,
) -> Optional[Dict[str, Any]]:
    referred_account_id = str(referred_account_id or "").strip()
    reason = str(reason or "").strip() or "manual_disqualification"

    if not referred_account_id:
        raise ValueError("referred_account_id is required")

    referral = get_referral_row_by_referred_account_id(referred_account_id)
    if not referral:
        return None

    now_iso = _now_iso()
    referral_id = str(referral.get("id") or "").strip()

    _sb().table("referrals").update(
        {
            "status": "disqualified",
            "disqualified_at": now_iso,
            "disqualify_reason": reason,
            "updated_at": now_iso,
        }
    ).eq("id", referral_id).execute()

    return get_referral_row_by_referred_account_id(referred_account_id)


def reverse_rewards_for_payment_reference(
    *,
    payment_reference: str,
    reversal_reason: str = "payment_refunded_or_reversed",
) -> Dict[str, Any]:
    payment_reference = str(payment_reference or "").strip()
    reversal_reason = str(reversal_reason or "").strip() or "payment_refunded_or_reversed"

    if not payment_reference:
        raise ValueError("payment_reference is required")

    rewards = get_reward_rows_by_payment_reference(payment_reference)
    if not rewards:
        return {
            "ok": True,
            "reversed_count": 0,
            "reason": "no_rewards_found",
        }

    now_iso = _now_iso()
    reversed_rows: List[Dict[str, Any]] = []

    for row in rewards:
        reward_id = str(row.get("id") or "").strip()
        if not reward_id:
            continue

        status = str(row.get("status") or "").strip().lower()
        if status == "reversed":
            reversed_rows.append(row)
            continue

        resp = (
            _sb()
            .table("referral_rewards")
            .update(
                {
                    "status": "reversed",
                    "reversed_at": now_iso,
                    "reversal_reason": reversal_reason,
                    "updated_at": now_iso,
                }
            )
            .eq("id", reward_id)
            .execute()
        )
        reversed_rows.append(_first(resp) or row)

    return {
        "ok": True,
        "reversed_count": len(reversed_rows),
        "rewards": reversed_rows,
    }


# =========================================================
# USER SUMMARY / HISTORY
# =========================================================

def get_referral_summary(account_id: str) -> Dict[str, Any]:
    account_id = str(account_id or "").strip()
    if not account_id:
        raise ValueError("account_id is required")

    # Mature eligible rewards first so dashboard is more accurate.
    _ = mature_pending_rewards(account_id=account_id, limit=1000)

    profile = ensure_referral_profile(account_id)

    referrals_resp = (
        _sb()
        .table("referrals")
        .select("*")
        .eq("referrer_account_id", account_id)
        .order("created_at", desc=True)
        .execute()
    )
    referrals = _response_data(referrals_resp)

    rewards_resp = (
        _sb()
        .table("referral_rewards")
        .select("*")
        .eq("account_id", account_id)
        .order("created_at", desc=True)
        .execute()
    )
    rewards = _response_data(rewards_resp)

    payouts_resp = (
        _sb()
        .table("referral_payouts")
        .select("*")
        .eq("account_id", account_id)
        .order("created_at", desc=True)
        .execute()
    )
    payouts = _response_data(payouts_resp)

    total_referrals = len(referrals)
    qualified_count = sum(
        1 for row in referrals if str(row.get("status") or "").strip().lower() in {"qualified", "rewarded"}
    )
    pending_referrals = sum(
        1 for row in referrals if str(row.get("status") or "").strip().lower() == "pending"
    )
    disqualified_referrals = sum(
        1 for row in referrals if str(row.get("status") or "").strip().lower() == "disqualified"
    )
    expired_referrals = sum(
        1 for row in referrals if str(row.get("status") or "").strip().lower() == "expired"
    )

    pending_rewards = Decimal("0")
    approved_rewards = Decimal("0")
    paid_rewards = Decimal("0")
    reversed_rewards = Decimal("0")

    level1_rewards = Decimal("0")
    level2_rewards = Decimal("0")

    for row in rewards:
        amount = _to_decimal(row.get("reward_amount"))
        status = str(row.get("status") or "").strip().lower()
        reward_type = str(row.get("reward_type") or "").strip().lower()

        if reward_type == "cash_level_1":
            level1_rewards += amount
        elif reward_type == "cash_level_2":
            level2_rewards += amount

        if status == _initial_reward_status():
            pending_rewards += amount
        elif status == _mature_reward_status():
            approved_rewards += amount
        elif status == "paid":
            paid_rewards += amount
        elif status == "reversed":
            reversed_rewards += amount

    available_balance = approved_rewards

    return {
        "profile": profile,
        "config": {
            "max_levels": _max_levels(),
            "level1_bonus": str(_level1_bonus()),
            "level2_bonus": str(_level2_bonus()),
            "hold_days": _hold_days(),
            "currency": _reward_currency(),
            "one_time_per_referred_user": _one_time_per_referred_user(),
        },
        "totals": {
            "total_referrals": total_referrals,
            "qualified_referrals": qualified_count,
            "pending_referrals": pending_referrals,
            "disqualified_referrals": disqualified_referrals,
            "expired_referrals": expired_referrals,
            "pending_rewards": str(pending_rewards),
            "approved_rewards": str(approved_rewards),
            "paid_rewards": str(paid_rewards),
            "reversed_rewards": str(reversed_rewards),
            "available_balance": str(available_balance),
            "level1_rewards_total": str(level1_rewards),
            "level2_rewards_total": str(level2_rewards),
            "currency": _reward_currency(),
            "payout_count": len(payouts),
        },
        "recent_referrals": referrals[:50],
        "recent_rewards": rewards[:50],
        "recent_payouts": payouts[:50],
    }


def list_referrals_for_referrer(account_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    account_id = str(account_id or "").strip()
    if not account_id:
        return []

    limit = max(1, min(_safe_int(limit, 100), 500))
    resp = (
        _sb()
        .table("referrals")
        .select("*")
        .eq("referrer_account_id", account_id)
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return _response_data(resp)


def list_rewards_for_account(account_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    account_id = str(account_id or "").strip()
    if not account_id:
        return []

    _ = mature_pending_rewards(account_id=account_id, limit=1000)

    limit = max(1, min(_safe_int(limit, 100), 500))
    resp = (
        _sb()
        .table("referral_rewards")
        .select("*")
        .eq("account_id", account_id)
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return _response_data(resp)


def list_payouts_for_account(account_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    account_id = str(account_id or "").strip()
    if not account_id:
        return []

    limit = max(1, min(_safe_int(limit, 100), 500))
    resp = (
        _sb()
        .table("referral_payouts")
        .select("*")
        .eq("account_id", account_id)
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return _response_data(resp)


# =========================================================
# PAYOUT BATCH HELPERS
# =========================================================

def get_approved_rewards_for_payout(account_id: str) -> List[Dict[str, Any]]:
    account_id = str(account_id or "").strip()
    if not account_id:
        return []

    _ = mature_pending_rewards(account_id=account_id, limit=1000)

    resp = (
        _sb()
        .table("referral_rewards")
        .select("*")
        .eq("account_id", account_id)
        .eq("status", _mature_reward_status())
        .order("created_at", desc=False)
        .execute()
    )
    return _response_data(resp)


def compute_approved_payout_balance(account_id: str) -> Decimal:
    rows = get_approved_rewards_for_payout(account_id)
    total = Decimal("0")
    for row in rows:
        total += _to_decimal(row.get("reward_amount"))
    return total
