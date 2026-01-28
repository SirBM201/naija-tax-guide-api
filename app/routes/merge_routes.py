import os
from flask import Blueprint, request, jsonify
from app.db.supabase_client import supabase
from app.core.security import safe_eq

bp = Blueprint("merge", __name__)
MERGE_SECRET = os.getenv("MERGE_SECRET", "").strip()

def _otp_verified(acct_id: str) -> bool:
    r = (
        supabase()
        .table("account_otps")
        .select("verified")
        .eq("acct_id", acct_id)
        .eq("purpose", "merge")
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    return bool(rows and rows[0].get("verified") is True)

@bp.post("/account/merge")
def merge():
    """
    Request JSON:
      {
        "primary_acct_id": "<uuid>",
        "secondary_acct_id": "<uuid>",
        "proof": { "type":"otp" } OR { "type":"secret", "value":"..." }
      }
    """
    d = request.get_json(silent=True) or {}
    primary = (d.get("primary_acct_id") or "").strip()
    secondary = (d.get("secondary_acct_id") or "").strip()
    proof = d.get("proof") or {}

    if not primary or not secondary or primary == secondary:
        return jsonify(ok=False, message="primary_acct_id and secondary_acct_id required (must differ)"), 400

    ptype = (proof.get("type") or "").strip().lower()

    if ptype == "otp":
        if not _otp_verified(primary):
            return jsonify(ok=False, message="merge OTP not verified for primary account"), 401
    elif ptype == "secret":
        if not MERGE_SECRET or not safe_eq(proof.get("value",""), MERGE_SECRET):
            return jsonify(ok=False, message="invalid merge secret"), 401
    else:
        return jsonify(ok=False, message="proof.type must be otp or secret"), 400

    # 1) Move identities from secondary -> primary
    supabase().table("account_identities").update({
        "acct_id": primary
    }).eq("acct_id", secondary).execute()

    # 2) Move subscription if primary doesn't have one but secondary has
    psub = supabase().table("subscriptions").select("*").eq("acct_id", primary).limit(1).execute()
    ssub = supabase().table("subscriptions").select("*").eq("acct_id", secondary).limit(1).execute()

    p_rows = getattr(psub, "data", None) or []
    s_rows = getattr(ssub, "data", None) or []

    if (not p_rows) and s_rows:
        supabase().table("subscriptions").upsert({
            "acct_id": primary,
            "plan": s_rows[0]["plan"],
            "status": s_rows[0]["status"],
            "expires_at": s_rows[0]["expires_at"],
        }).execute()

    # 3) Delete secondary subscription row (avoid orphan)
    supabase().table("subscriptions").delete().eq("acct_id", secondary).execute()

    # 4) Delete secondary account if it has no identities left
    left = supabase().table("account_identities").select("acct_id").eq("acct_id", secondary).limit(1).execute()
    if not (getattr(left, "data", None) or []):
        supabase().table("accounts").delete().eq("acct_id", secondary).execute()

    return jsonify(ok=True, primary_acct_id=primary, merged_secondary=secondary), 200
