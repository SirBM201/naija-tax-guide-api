def get_active_session(supabase, wa_phone):
    res = (
        supabase.table("flow_sessions")
        .select("*")
        .eq("wa_phone", wa_phone)
        .eq("status", "active")
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def create_session(supabase, wa_phone, flow_key, start_step):
    return (
        supabase.table("flow_sessions")
        .insert({
            "wa_phone": wa_phone,
            "flow_key": flow_key,
            "status": "active",
            "current_step": start_step,
            "step_index": 1,
            "context": {}
        })
        .execute()
    )


def update_session(supabase, session_id, **updates):
    updates["updated_at"] = "now()"
    return (
        supabase.table("flow_sessions")
        .update(updates)
        .eq("id", session_id)
        .execute()
    )
