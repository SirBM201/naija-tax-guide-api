def log_event(supabase, wa_phone, event, meta=None):
    supabase.table("events").insert({
        "wa_phone": wa_phone,
        "event": event,
        "meta": meta or {}
    }).execute()
