from __future__ import annotations

import inspect
import re
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase
from app.services.accounts_service import lookup_account, upsert_account
from app.services.ask_service import ask_guarded
from app.services.channel_linking_service import consume_and_link, extract_code
from app.services.outbound_service import send_telegram_text
from app.services.channel_identity_runtime_service import sync_channel_identity_runtime

bp = Blueprint("telegram", __name__)


WELCOME_MENU = (
    "Welcome to Naija Tax Guide ✅\n\n"
    "Reply with:\n"
    "1 — Ask a tax question\n"
    "2 — Check AI credits balance\n"
    "3 — Check current plan\n"
    "4 — Upgrade subscription\n"
    "5 — Link website account\n"
    "6 — Help / how to use this bot\n\n"
    "You can also type your tax question directly at any time."
)

HELP_TEXT = (
    "How to use Naija Tax Guide on Telegram:\n\n"
    "• Send 1 to start asking a tax question\n"
    "• Send 2 to check AI credits balance\n"
    "• Send 3 to check your current plan\n"
    "• Send 4 to view upgrade options\n"
    "• Send 5 if you want to link your website account\n"
    "• Send 6 to see this help again\n\n"
    "You can also type a full tax question directly, for example:\n"
    "“What expenses are deductible for a small business in Nigeria?”"
)

LINK_TEXT = (
    "Website account linking is optional.\n\n"
    "If you already use the website and want this Telegram account connected to it:\n"
    "1) Login on the website\n"
    "2) Generate your LINK CODE\n"
    "3) Reply here with the 8-character code\n\n"
    "Example: 7K9M2H8P"
)

UPGRADE_TEXT = (
    "Available plan options:\n\n"
    "Starter:\n"
    "• starter_monthly\n"
    "• starter_quarterly\n"
    "• starter_yearly\n\n"
    "Professional:\n"
    "• professional_monthly\n"
    "• professional_quarterly\n"
    "• professional_yearly\n\n"
    "Business:\n"
    "• business_monthly\n"
    "• business_quarterly\n"
    "• business_yearly\n\n"
    "You can say things naturally, for example:\n"
    "• I want professional monthly\n"
    "• Give me starter quarterly\n"
    "• I need business yearly"
)

TIER_ALIASES = {
    "starter": ["starter", "basic", "beginner", "small"],
    "professional": ["professional", "pro", "premium"],
    "business": ["business", "biz", "company"],
}

PERIOD_ALIASES = {
    "monthly": ["monthly", "month", "per month", "every month", "30 days"],
    "quarterly": ["quarterly", "quarter", "3 months", "three months", "90 days"],
    "yearly": ["yearly", "year", "annual", "annually", "12 months", "one year", "365 days"],
}


def _sb():
    return supabase() if callable(supabase) else supabase


def _clip(value: Any, limit: int = 260) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[:limit] + "…"


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _menu_trigger(text: str) -> bool:
    lowered = _clean(text).lower()
    return lowered in {"hi", "hello", "hey", "/start", "start", "good morning", "good afternoon", "good evening"}


def _normalize_text(text: str) -> str:
    lowered = _clean(text).lower()
    lowered = lowered.replace("-", " ").replace("_", " ")
    lowered = re.sub(r"[^\w\s]", " ", lowered)
    lowered = re.sub(r"\s+", " ", lowered).strip()
    return lowered


def _contains_phrase(text: str, phrase: str) -> bool:
    return phrase in text


def _detect_plan_intent(text: str) -> Dict[str, Any]:
    """
    Detect natural-language plan requests.

    Examples:
    - professional monthly
    - i want pro monthly
    - give me business yearly
    - starter plan
    """
    raw = _clean(text)
    normalized = _normalize_text(raw)

    if not normalized:
        return {"ok": False}

    # exact plan code support
    exact_codes = [
        "starter_monthly",
        "starter_quarterly",
        "starter_yearly",
        "professional_monthly",
        "professional_quarterly",
        "professional_yearly",
        "business_monthly",
        "business_quarterly",
        "business_yearly",
    ]
    for code in exact_codes:
        if code in raw.lower() or code.replace("_", " ") in normalized:
            tier, period = code.split("_", 1)
            return {
                "ok": True,
                "matched": True,
                "tier": tier,
                "period": period,
                "plan_code": code,
                "confidence": "high",
            }

    tier_found: Optional[str] = None
    for tier, aliases in TIER_ALIASES.items():
        if any(_contains_phrase(normalized, alias) for alias in aliases):
            tier_found = tier
            break

    period_found: Optional[str] = None
    for period, aliases in PERIOD_ALIASES.items():
        if any(_contains_phrase(normalized, alias) for alias in aliases):
            period_found = period
            break

    if tier_found and period_found:
        return {
            "ok": True,
            "matched": True,
            "tier": tier_found,
            "period": period_found,
            "plan_code": f"{tier_found}_{period_found}",
            "confidence": "medium",
        }

    if tier_found:
        return {
            "ok": True,
            "matched": True,
            "tier": tier_found,
            "period": None,
            "plan_code": None,
            "confidence": "partial",
        }

    return {"ok": False}


def _build_ask_payload(*, account_id: str, tg_user_id: str, text: str) -> Dict[str, Any]:
    clean_text = (text or "").strip()
    return {
        "account_id": account_id,
        "provider": "tg",
        "channel": "tg",
        "platform": "telegram",
        "source": "telegram",
        "provider_user_id": tg_user_id,
        "channel_user_id": tg_user_id,
        "question": clean_text,
        "query": clean_text,
        "text": clean_text,
        "message": clean_text,
        "user_message": clean_text,
        "user_query": clean_text,
        "lang": "en",
        "mode": "text",
    }


def _call_ask_guarded(payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        sig = inspect.signature(ask_guarded)
        params = list(sig.parameters.values())

        has_var_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)
        accepted_names = {
            p.name
            for p in params
            if p.kind in (
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            )
        }

        filtered_kwargs = {k: v for k, v in payload.items() if has_var_kwargs or k in accepted_names}

        missing_required = []
        for p in params:
            if p.kind in (
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            ):
                if p.default is inspect._empty and p.name not in filtered_kwargs:
                    missing_required.append(p.name)

        if missing_required:
            return {
                "ok": False,
                "error": "ask_guarded_signature_mismatch",
                "root_cause": f"Missing required ask_guarded args: {', '.join(missing_required)}",
                "fix": "Align Telegram payload keys with app.services.ask_service.ask_guarded signature.",
                "details": {
                    "accepted_names": sorted(list(accepted_names)),
                    "payload_keys": sorted(list(payload.keys())),
                },
            }

        resp = ask_guarded(**filtered_kwargs)
        if isinstance(resp, dict):
            return resp

        return {
            "ok": False,
            "error": "ask_guarded_invalid_response",
            "root_cause": f"ask_guarded returned non-dict response: {type(resp).__name__}",
            "fix": "Ensure ask_guarded returns a dict with answer/message metadata.",
            "details": {"response_type": str(type(resp))},
        }
    except Exception as e:
        return {
            "ok": False,
            "error": "ask_guarded_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
            "fix": "Check app.services.ask_service.ask_guarded expected signature and internal dependencies.",
            "details": {"payload": payload},
        }


def _safe_sync_runtime_identity(
    *,
    account_id: str,
    tg_user_id: str,
    telegram_chat_id: str,
    display_name: str | None,
    username: str | None,
    chat_type: str | None,
) -> Dict[str, Any]:
    try:
        return sync_channel_identity_runtime(
            account_id=account_id,
            channel_type="telegram",
            provider_user_id=str(tg_user_id).strip(),
            display_name=display_name,
            metadata_patch={
                "telegram_username": (username or "").strip() or None,
                "telegram_chat_type": (chat_type or "").strip() or None,
                "telegram_runtime_sync": True,
                "telegram_chat_id": str(telegram_chat_id).strip() if telegram_chat_id else None,
                "last_runtime_chat_id": str(telegram_chat_id).strip() if telegram_chat_id else None,
            },
        )
    except Exception as e:
        return {
            "ok": False,
            "error": "telegram_runtime_sync_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
            "fix": "Check app.services.channel_identity_runtime_service.sync_channel_identity_runtime and channel_identities table shape.",
        }


def _extract_account_id(shell: Dict[str, Any], lookup: Dict[str, Any]) -> str:
    return str(
        lookup.get("account_id")
        or shell.get("account_id")
        or shell.get("id")
        or ""
    ).strip()


def _send_guest_welcome(chat_id: Any) -> None:
    send_telegram_text(chat_id, WELCOME_MENU)


def _fetch_latest_daily_usage(account_id: str) -> Dict[str, Any]:
    """
    Schema-tolerant fetch for ai_daily_usage.
    """
    table = _sb().table("ai_daily_usage").select("*").eq("account_id", account_id)

    attempts = [
        ("updated_at", True),
        ("created_at", True),
        (None, False),
    ]

    last_error: Optional[str] = None

    for column, do_order in attempts:
        try:
            query = table
            if do_order and column:
                query = query.order(column, desc=True)
            res = query.limit(1).execute()
            rows = getattr(res, "data", None) or []
            return {
                "ok": True,
                "row": rows[0] if rows else {},
            }
        except Exception as e:
            last_error = f"{type(e).__name__}: {_clip(e)}"

    return {
        "ok": False,
        "error": "daily_usage_lookup_failed",
        "root_cause": last_error or "Unknown ai_daily_usage lookup failure",
    }


def _get_credit_summary(account_id: str) -> Dict[str, Any]:
    acct = _clean(account_id)
    if not acct:
        return {
            "ok": False,
            "error": "account_id_required",
            "fix": "Account id is required for credit lookup.",
        }

    try:
        balance_res = (
            _sb()
            .table("ai_credit_balances")
            .select("*")
            .eq("account_id", acct)
            .limit(1)
            .execute()
        )
        balance_rows = getattr(balance_res, "data", None) or []
        balance_row = balance_rows[0] if balance_rows else {}

        daily_result = _fetch_latest_daily_usage(acct)
        daily_row = daily_result.get("row") or {}

        if not daily_result.get("ok"):
            return {
                "ok": False,
                "error": "credit_lookup_failed",
                "root_cause": daily_result.get("root_cause"),
                "fix": "Check ai_credit_balances and ai_daily_usage table access.",
            }

        return {
            "ok": True,
            "balance_row": balance_row,
            "daily_row": daily_row,
        }
    except Exception as e:
        return {
            "ok": False,
            "error": "credit_lookup_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
            "fix": "Check ai_credit_balances and ai_daily_usage table access.",
        }


def _format_credit_summary(summary: Dict[str, Any]) -> str:
    if not summary.get("ok"):
        return (
            "❌ Could not check AI credits right now.\n"
            f"Reason: {summary.get('error', 'unknown_error')}\n"
            f"Details: {_clip(summary.get('root_cause') or 'n/a')}\n"
            f"Fix: {_clip(summary.get('fix') or 'Check backend credit tables.')}"
        )

    balance_row = summary.get("balance_row") or {}
    daily_row = summary.get("daily_row") or {}

    balance = balance_row.get("balance")
    updated_at = balance_row.get("updated_at")
    used_today = (
        daily_row.get("used_today")
        or daily_row.get("count")
        or daily_row.get("usage_count")
        or daily_row.get("questions_used")
        or daily_row.get("used")
    )
    usage_date = (
        daily_row.get("usage_date")
        or daily_row.get("date")
        or daily_row.get("created_at")
        or daily_row.get("updated_at")
    )

    return (
        "AI Credits Summary:\n\n"
        f"Current balance: {balance if balance is not None else 'Not available'}\n"
        f"Used recently: {used_today if used_today is not None else 'Not available'}\n"
        f"Usage record date: {usage_date or 'Not available'}\n"
        f"Last updated: {updated_at or 'Not available'}"
    )


def _get_plan_summary(account_id: str) -> Dict[str, Any]:
    acct = _clean(account_id)
    if not acct:
        return {
            "ok": False,
            "error": "account_id_required",
            "fix": "Account id is required for plan lookup.",
        }

    try:
        sub_res = (
            _sb()
            .table("user_subscriptions")
            .select("*")
            .eq("account_id", acct)
            .order("created_at", desc=True)
            .limit(3)
            .execute()
        )
        rows = getattr(sub_res, "data", None) or []

        active_row = None
        for row in rows:
            if row.get("is_active") is True or str(row.get("status") or "").lower() in {"active", "trialing"}:
                active_row = row
                break

        chosen = active_row or (rows[0] if rows else {})
        return {
            "ok": True,
            "subscription": chosen,
        }
    except Exception as e:
        return {
            "ok": False,
            "error": "plan_lookup_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
            "fix": "Check user_subscriptions table access and columns.",
        }


def _format_plan_summary(summary: Dict[str, Any]) -> str:
    if not summary.get("ok"):
        return (
            "❌ Could not check your current plan right now.\n"
            f"Reason: {summary.get('error', 'unknown_error')}\n"
            f"Details: {_clip(summary.get('root_cause') or 'n/a')}\n"
            f"Fix: {_clip(summary.get('fix') or 'Check backend subscription tables.')}"
        )

    sub = summary.get("subscription") or {}
    if not sub:
        return (
            "Current Plan:\n\n"
            "No active subscription found.\n"
            "Send 4 if you want to see upgrade options."
        )

    plan_code = sub.get("plan_code") or "Not available"
    status = sub.get("status") or ("active" if sub.get("is_active") else "inactive")
    started_at = sub.get("started_at") or sub.get("starts_at") or sub.get("created_at")
    expires_at = sub.get("expires_at") or sub.get("ends_at") or sub.get("grace_until") or sub.get("trial_until")

    return (
        "Current Plan:\n\n"
        f"Plan code: {plan_code}\n"
        f"Status: {status}\n"
        f"Started: {started_at or 'Not available'}\n"
        f"Expires: {expires_at or 'Not available'}"
    )


def _handle_plan_phrase(
    *,
    chat_id: Any,
    text: str,
    linked: bool,
    runtime_sync: Dict[str, Any] | None,
) -> Any:
    plan_match = _detect_plan_intent(text)
    if not plan_match.get("ok"):
        return None

    tier = plan_match.get("tier")
    period = plan_match.get("period")
    plan_code = plan_match.get("plan_code")

    if tier and not period:
        send_telegram_text(
            chat_id,
            f"I recognized the {tier} plan.\n\n"
            "Which billing cycle do you want?\n"
            "• monthly\n"
            "• quarterly\n"
            "• yearly\n\n"
            f"Example:\n{tier}_monthly",
        )
        return jsonify(
            {
                "ok": True,
                "linked": linked,
                "mode": "plan_tier_detected",
                "runtime_sync": runtime_sync,
                "plan_match": plan_match,
            }
        )

    if plan_code:
        send_telegram_text(
            chat_id,
            f"I recognized your selected plan as:\n{plan_code}\n\n"
            "That looks good.\n"
            "The next step is payment initialization for that plan.\n"
            "You can also still ask tax questions here anytime.",
        )
        return jsonify(
            {
                "ok": True,
                "linked": linked,
                "mode": "plan_code_detected",
                "runtime_sync": runtime_sync,
                "plan_match": plan_match,
            }
        )

    return None


def _handle_question(
    *,
    chat_id: Any,
    account_id: str,
    tg_user_id: str,
    text: str,
    runtime_sync: Dict[str, Any] | None = None,
    linked: bool = False,
) -> Any:
    payload = _build_ask_payload(account_id=account_id, tg_user_id=tg_user_id, text=text)
    resp = _call_ask_guarded(payload)

    if not resp.get("ok") and not (resp.get("answer") or resp.get("message")):
        send_telegram_text(
            chat_id,
            "❌ Question processing failed.\n"
            f"Reason: {resp.get('error', 'unknown_error')}\n"
            f"Details: {_clip(resp.get('root_cause') or resp.get('details') or 'n/a')}\n"
            f"Fix: {_clip(resp.get('fix') or 'Check ask_guarded integration and backend AI flow.')}",
        )
        return jsonify(
            {
                "ok": False,
                "stage": "ask_failed",
                "details": resp,
                "runtime_sync": runtime_sync,
                "linked": linked,
            }
        ), 200

    answer = (resp.get("answer") or resp.get("message") or "").strip()
    if not answer:
        answer = "I couldn't process that right now. Please try again."

    send_telegram_text(chat_id, answer)
    return jsonify(
        {
            "ok": True,
            "linked": linked,
            "ask": resp,
            "runtime_sync": runtime_sync,
        }
    )


def _handle_menu_option(
    *,
    option: str,
    chat_id: Any,
    account_id: str,
    tg_user_id: str,
    runtime_sync: Dict[str, Any] | None,
    linked: bool,
) -> Any:
    if option == "1":
        send_telegram_text(
            chat_id,
            "Send your tax question now.\n\n"
            "Example:\n"
            "What expenses are deductible for a small business in Nigeria?",
        )
        return jsonify(
            {
                "ok": True,
                "linked": linked,
                "mode": "ask_prompt",
                "runtime_sync": runtime_sync,
            }
        )

    if option == "2":
        summary = _get_credit_summary(account_id)
        send_telegram_text(chat_id, _format_credit_summary(summary))
        return jsonify(
            {
                "ok": True,
                "linked": linked,
                "mode": "credits_balance",
                "runtime_sync": runtime_sync,
                "credits": summary,
            }
        )

    if option == "3":
        summary = _get_plan_summary(account_id)
        send_telegram_text(chat_id, _format_plan_summary(summary))
        return jsonify(
            {
                "ok": True,
                "linked": linked,
                "mode": "plan_summary",
                "runtime_sync": runtime_sync,
                "plan": summary,
            }
        )

    if option == "4":
        send_telegram_text(chat_id, UPGRADE_TEXT)
        return jsonify(
            {
                "ok": True,
                "linked": linked,
                "mode": "upgrade_menu",
                "runtime_sync": runtime_sync,
            }
        )

    if option == "5":
        send_telegram_text(chat_id, LINK_TEXT)
        return jsonify(
            {
                "ok": True,
                "linked": linked,
                "mode": "link_help",
                "runtime_sync": runtime_sync,
            }
        )

    if option == "6":
        send_telegram_text(chat_id, HELP_TEXT)
        return jsonify(
            {
                "ok": True,
                "linked": linked,
                "mode": "help",
                "runtime_sync": runtime_sync,
            }
        )

    return _handle_question(
        chat_id=chat_id,
        account_id=account_id,
        tg_user_id=tg_user_id,
        text=option,
        runtime_sync=runtime_sync,
        linked=linked,
    )


@bp.post("/telegram/webhook")
def tg_webhook():
    """
    Channel-first Telegram behavior:
    - User can start directly from Telegram
    - Referral is optional
    - Website linking is optional
    - Menu-driven onboarding for hi/hello/start
    - Direct-question fallback remains available
    - Natural-language plan recognition is supported
    """
    update = request.get_json(silent=True) or {}

    msg = update.get("message") or update.get("edited_message") or {}
    if not msg:
        return jsonify({"ok": True, "ignored": True})

    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    chat_type = chat.get("type")

    text = (msg.get("text") or "").strip()

    user = msg.get("from") or {}
    tg_user_id = str(user.get("id") or "").strip()
    tg_username = (user.get("username") or "").strip() or None

    display_name = " ".join(
        [x for x in [user.get("first_name"), user.get("last_name")] if x]
    ) or None

    if not tg_user_id or not chat_id:
        return jsonify({"ok": True, "ignored": True})

    shell = upsert_account(
        provider="tg",
        provider_user_id=tg_user_id,
        display_name=display_name,
        phone=None,
    )
    if not shell.get("ok"):
        send_telegram_text(
            chat_id,
            "❌ Telegram shell account setup failed.\n"
            f"Reason: {shell.get('error', 'unknown_error')}\n"
            f"Details: {_clip(shell.get('root_cause') or shell.get('details') or 'n/a')}\n"
            f"Fix: {_clip(shell.get('fix') or 'Check backend account setup.')}",
        )
        return jsonify({"ok": False, "stage": "upsert_shell", "details": shell}), 200

    lk = lookup_account(provider="tg", provider_user_id=tg_user_id)
    if not lk.get("ok"):
        send_telegram_text(
            chat_id,
            "❌ Telegram account lookup failed.\n"
            f"Reason: {lk.get('error', 'lookup_failed')}\n"
            f"Details: {_clip(lk.get('root_cause') or lk.get('details') or 'n/a')}\n"
            f"Fix: {_clip(lk.get('fix') or 'Check accounts table access.')}",
        )
        return jsonify({"ok": False, "stage": "lookup_account", "details": lk}), 200

    account_id = _extract_account_id(shell, lk)
    if not account_id:
        send_telegram_text(
            chat_id,
            "❌ Telegram account creation succeeded but no account_id is available.\n"
            "Fix: Ensure upsert_account / lookup_account returns canonical account_id.",
        )
        return jsonify(
            {
                "ok": False,
                "stage": "missing_account_id",
                "shell": shell,
                "lookup": lk,
            }
        ), 200

    runtime_sync = _safe_sync_runtime_identity(
        account_id=account_id,
        tg_user_id=tg_user_id,
        telegram_chat_id=str(chat_id),
        display_name=display_name,
        username=tg_username,
        chat_type=chat_type,
    )

    linked = bool(lk.get("linked"))

    code = extract_code(text)
    if code:
        attempt = consume_and_link(
            provider="tg",
            code=code,
            provider_user_id=tg_user_id,
            display_name=display_name,
            phone=None,
        )

        if attempt.get("ok"):
            linked_account_id = str(attempt.get("account_id") or account_id).strip()
            runtime_sync = _safe_sync_runtime_identity(
                account_id=linked_account_id,
                tg_user_id=tg_user_id,
                telegram_chat_id=str(chat_id),
                display_name=display_name,
                username=tg_username,
                chat_type=chat_type,
            )

            send_telegram_text(
                chat_id,
                "✅ Telegram linked successfully!\n"
                "Your Telegram can now work with your website account too.\n"
                "Send your tax question anytime.",
            )
            return jsonify(
                {
                    "ok": True,
                    "linked": True,
                    "linked_now": True,
                    "account_id": attempt.get("account_id"),
                    "auth_user_id": attempt.get("auth_user_id"),
                    "runtime_sync": runtime_sync,
                }
            )

        send_telegram_text(
            chat_id,
            "❌ Link failed.\n"
            f"Reason: {attempt.get('error', 'unknown_error')}\n"
            f"Details: {_clip(attempt.get('root_cause') or attempt.get('details') or 'n/a')}\n"
            f"Fix: {_clip(attempt.get('fix') or 'Check link token flow and accounts link update.')}",
        )
        return jsonify({"ok": True, "linked": linked, "link_attempt": attempt}), 200

    if not text:
        send_telegram_text(chat_id, "Send a message to continue.\n\n" + WELCOME_MENU)
        return jsonify(
            {
                "ok": True,
                "linked": linked,
                "ignored": True,
                "reason": "no_text",
                "runtime_sync": runtime_sync,
            }
        )

    if _menu_trigger(text):
        _send_guest_welcome(chat_id)
        return jsonify(
            {
                "ok": True,
                "linked": linked,
                "runtime_sync": runtime_sync,
                "mode": "guest_or_linked_welcome",
            }
        )

    lowered = text.lower().strip()
    if lowered in {"1", "2", "3", "4", "5", "6"}:
        return _handle_menu_option(
            option=lowered,
            chat_id=chat_id,
            account_id=account_id,
            tg_user_id=tg_user_id,
            runtime_sync=runtime_sync,
            linked=linked,
        )

    plan_response = _handle_plan_phrase(
        chat_id=chat_id,
        text=text,
        linked=linked,
        runtime_sync=runtime_sync,
    )
    if plan_response is not None:
        return plan_response

    return _handle_question(
        chat_id=chat_id,
        account_id=account_id,
        tg_user_id=tg_user_id,
        text=text,
        runtime_sync=runtime_sync,
        linked=linked,
    )
