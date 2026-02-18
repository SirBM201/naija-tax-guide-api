from __future__ import annotations

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from ..core.supabase_client import supabase
from ..core import config
from ..services.ask_service import ask_chat_guarded


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def create_session(account_id: str, title: Optional[str] = None) -> Dict[str, Any]:
    payload = {
        "account_id": account_id,
        "title": (title or "New chat").strip()[:80] or "New chat",
        "created_at": _iso(_now_utc()),
        "updated_at": _iso(_now_utc()),
    }
    res = supabase().table(config.WEB_CHAT_SESSIONS_TABLE).insert(payload).execute()
    if not getattr(res, "data", None):
        raise RuntimeError("failed_to_create_session")
    return res.data[0]


def list_sessions(account_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    res = (
        supabase()
        .table(config.WEB_CHAT_SESSIONS_TABLE)
        .select("id,title,created_at,updated_at")
        .eq("account_id", account_id)
        .order("updated_at", desc=True)
        .limit(limit)
        .execute()
    )
    return getattr(res, "data", None) or []


def get_session(account_id: str, session_id: str) -> Optional[Dict[str, Any]]:
    res = (
        supabase()
        .table(config.WEB_CHAT_SESSIONS_TABLE)
        .select("*")
        .eq("id", session_id)
        .eq("account_id", account_id)
        .limit(1)
        .execute()
    )
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else None


def get_messages(account_id: str, session_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    res = (
        supabase()
        .table(config.WEB_CHAT_MESSAGES_TABLE)
        .select("id,role,content,created_at")
        .eq("account_id", account_id)
        .eq("session_id", session_id)
        .order("created_at", desc=False)
        .limit(limit)
        .execute()
    )
    return getattr(res, "data", None) or []


def append_message(account_id: str, session_id: str, role: str, content: str) -> Dict[str, Any]:
    role = (role or "").strip().lower()
    if role not in {"user", "assistant", "system"}:
        raise ValueError("invalid_role")

    payload = {
        "account_id": account_id,
        "session_id": session_id,
        "role": role,
        "content": (content or "").strip(),
        "created_at": _iso(_now_utc()),
    }

    res = supabase().table(config.WEB_CHAT_MESSAGES_TABLE).insert(payload).execute()
    if not getattr(res, "data", None):
        raise RuntimeError("failed_to_append_message")

    supabase().table(config.WEB_CHAT_SESSIONS_TABLE).update({"updated_at": _iso(_now_utc())}).eq(
        "id", session_id
    ).eq("account_id", account_id).execute()

    return res.data[0]


def send_user_message(*, account_id: str, session_id: str, content: str, history_limit: int = 12) -> Dict[str, Any]:
    session = get_session(account_id, session_id)
    if not session:
        raise ValueError("session_not_found")

    user_text = (content or "").strip()
    if not user_text:
        raise ValueError("message_required")

    user_msg = append_message(account_id, session_id, "user", user_text)

    msgs = get_messages(account_id, session_id, limit=max(history_limit, 1) * 2)

    llm_msgs: List[Dict[str, str]] = []
    for m in msgs[-(history_limit * 2) :]:
        role = (m.get("role") or "").strip().lower()
        if role not in {"user", "assistant", "system"}:
            continue
        llm_msgs.append({"role": role, "content": m.get("content") or ""})

    ai = ask_chat_guarded(messages=llm_msgs, account_id=account_id, provider="web")
    assistant_text = (ai.get("answer") or "").strip()

    assistant_msg = append_message(account_id, session_id, "assistant", assistant_text)

    return {
        "ok": True,
        "session": {"id": session.get("id"), "title": session.get("title"), "updated_at": session.get("updated_at")},
        "user_message": {"id": user_msg.get("id"), "role": "user", "content": user_text, "created_at": user_msg.get("created_at")},
        "assistant_message": {"id": assistant_msg.get("id"), "role": "assistant", "content": assistant_text, "created_at": assistant_msg.get("created_at")},
    }
