import os
import logging
from flask import Blueprint, request, jsonify, current_app
from app.db.supabase_client import supabase
from app.core.security import make_otp_code, otp_expires_at, sha256_hex, throttle, OTP_DEV_MODE

bp = Blueprint("otp", __name__)
log = logging.getLogger(__name__)

MAX_PER_15 = int(os.getenv("OTP_MAX_SEND_PER_15MIN", "5"))
MERGE_SECRET = os.getenv("MERGE_SECRET", "").strip()

@bp.post("/otp/request")
def otp_request():
    """
    Request JSON:
      { "acct_id": "<uuid>", "purpose": "login|merge", "channel":"web|wa|tg" }

    Response:
      { ok:true }
      (in dev mode: returns otp code)
    """
    d = request.get_json(silent=True) or {}
    acct_id = (d.get("acct_id") or "").strip()
    purpose = (d.get("purpose") or "login").strip()
    channel = (d.get("channel") or "web").strip()

    if not acct_id:
        return jsonify(ok=False, message="acct_id required"), 400

    key = f"otp:{acct_id}:{purpose}"
    if not throttle.allow(key, max_events=MAX_PER_15, window_seconds=900):
        return jsonify(ok=False, message="Too many OTP requests. Try later."), 429

    code = make_otp_code()
    exp = otp_expires_at()
    code_hash = sha256_hex(code)

    supabase().table("account_otps").insert({
        "acct_id": acct_id,
        "purpose": purpose,
        "channel": channel,
        "code_hash": code_hash,
        "expires_at": exp.isoformat(),
        "verified": False
    }).execute()

    # Optional: send OTP via WA/TG by calling your own internal send endpoints later.
    # For now: web channel returns success. WA/TG send can be added once you want it.
    # You can still test OTP end-to-end using DEV mode.

    resp = {"ok": True}
    if OTP_DEV_MODE:
        resp["otp"] = code
        resp["dev_note"] = "OTP_DEV_MODE=1 so OTP is returned for testing."

    return jsonify(resp), 200

@bp.post("/otp/verify")
def otp_verify():
    """
    Request JSON:
      { "acct_id":"<uuid>", "purpose":"login|merge", "otp":"123456" }

    Response:
      { ok:true, verified:true }
    """
    d = request.get_json(silent=True) or {}
    acct_id = (d.get("acct_id") or "").strip()
    purpose = (d.get("purpose") or "login").strip()
    otp = (d.get("otp") or "").strip()

    if not acct_id or not otp:
        return jsonify(ok=False, message="acct_id and otp required"), 400

    otp_hash = sha256_hex(otp)

    # Find latest unverified OTP for this acct/purpose
    r = (
        supabase()
        .table("account_otps")
        .select("otp_id,code_hash,expires_at,verified")
        .eq("acct_id", acct_id)
        .eq("purpose", purpose)
        .eq("verified", False)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if not rows:
        return jsonify(ok=False, message="No pending OTP found"), 400

    row = rows[0]
    exp = row.get("expires_at")
    if not exp:
        return jsonify(ok=False, message="OTP invalid"), 400

    # expiry check
    from datetime import datetime, timezone
    exp_dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
    if exp_dt <= datetime.now(timezone.utc):
        return jsonify(ok=False, message="OTP expired"), 400

    if row.get("code_hash") != otp_hash:
        return jsonify(ok=False, message="OTP incorrect"), 401

    # mark verified
    supabase().table("account_otps").update({"verified": True}).eq("otp_id", row["otp_id"]).execute()
    return jsonify(ok=True, verified=True), 200
