from supabase import create_client
import os
from datetime import datetime

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


def get_active_session(phone: str, flow_key: str):
    res = (
        supabase.table("flow_sessions")
        .select("*")
        .eq("phone", phone)
        .eq("flow_key", flow_key)
        .eq("is_active", True)
        .single()
        .execute()
    )
    return res.data if res.data else None


def create_session(phone: str, flow_key: str, state: str):
    return (
        supabase.table("flow_sessions")
        .insert({
            "phone": phone,
            "flow_key": flow_key,
            "state": state,
            "step": 1,
        })
        .execute()
    )


def update_session(session_id: str, state=None, step=None, data=None):
    payload = {"last_message_at": datetime.utcnow().isoformat()}
    if state:
        payload["state"] = state
    if step:
        payload["step"] = step
    if data:
        payload["data"] = data

    return (
        supabase.table("flow_sessions")
        .update(payload)
        .eq("id", session_id)
        .execute()
    )


def close_session(session_id: str):
    return (
        supabase.table("flow_sessions")
        .update({"is_active": False})
        .eq("id", session_id)
        .execute()
    )
