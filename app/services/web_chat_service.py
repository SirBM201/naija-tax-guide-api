from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from app.core.supabase_client import supabase
from app.services.ask_service import ask_guarded


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def list_sessions(account_id: str) -> List[Dict[str, Any]]:
    res = (
        supabase.table("web_chat_sessions")
        .select("id, title, created_at, updated_at")
        .eq("account_id", account_id)
        .order("updated_at", desc=True)
        .execute()
    )
    return res.data or []


def create_session(account_id: str, title: str) -> Dict[str, Any]:
    now = _iso_now()
    res = (
        supabase.table("web_chat_sessions")
        .insert(
            {
                "account_id": account_id,
                "title": title,
                "created_at": now,
                "updated_at": now,
            }
        )
        .select("id, title, created_at, updated_at")
        .execute()
    )
    return (res.data or [{}])[0]


def get_messages(account_id: str, session_id: str) -> List[Dict[str, Any]]:
    s = (
        supabase.table("web_chat_sessions")
        .select("id")
        .eq("id", session_id)
        .eq("account_id", account_id)
        .limit(1)
        .execute()
    )
    if not (s.data or []):
        return []

    res = (
        supabase.table("web_chat_messages")
        .select("id, role, content, created_at")
        .eq("session_id", session_id)
        .eq("account_id", account_id)
        .order("created_at", desc=False)
        .execute()
    )
    return res.data or []


def _append_message(account_id: str, session_id: str, role: str, content: str) -> None:
    supabase.table("web_chat_messages").insert(
        {
            "account_id": account_id,
            "session_id": session_id,
            "role": role,
            "content": content,
        }
    ).execute()

    supabase.table("web_chat_sessions").update(
        {"updated_at": _iso_now()}
    ).eq("id", session_id).eq("account_id", account_id).execute()


def send_message(account_id: str, session_id: str, text: str) -> Dict[str, Any]:
    s = (
        supabase.table("web_chat_sessions")
        .select("id")
        .eq("id", session_id)
        .eq("account_id", account_id)
        .limit(1)
        .execute()
    )
    if not (s.data or []):
        new_s = create_session(account_id, title="New chat")
        session_id = new_s["id"]

    _append_message(account_id, session_id, "user", text)

    history = (
        supabase.table("web_chat_messages")
        .select("role, content")
        .eq("session_id", session_id)
        .eq("account_id", account_id)
        .order("created_at", desc=True)
        .limit(12)
        .execute()
    ).data or []

    history = list(reversed(history))
    context_lines = []
    for m in history:
        role = m.get("role")
        content = str(m.get("content") or "").strip()
        if not content:
            continue
        prefix = "User" if role == "user" else "Assistant"
        context_lines.append(f"{prefix}: {content}")

    combined = "\n".join(context_lines).strip()

    result = ask_guarded(
        account_id=str(account_id or "").strip(),
        question=combined,
        lang="en",
        channel="web_chat",
    )

    if not result.get("ok"):
        return {
            "ok": False,
            "error": result.get("error") or "ask_failed",
            "details": result,
            "session_id": session_id,
        }

    answer = str(result.get("answer") or "").strip()
    _append_message(account_id, session_id, "assistant", answer)

    return {
        "ok": True,
        "session_id": session_id,
        "answer": answer,
        "ask": result,
    }
