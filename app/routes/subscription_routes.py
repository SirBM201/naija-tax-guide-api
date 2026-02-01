from flask import Blueprint, request, jsonify

from app.core.identity import ensure_account, normalize_provider
from app.core.subscriptions import get_subscription_by_acct_key
from app.core.utils import json_error

bp = Blueprint("subscription", __name__)

@bp.post("/subscription/status")
def subscription_status():
    body = request.get_json(silent=True) or {}
    provider = normalize_provider(body.get("provider") or "web")
    provider_user_id = (body.get("provider_user_id") or "").strip()
    if not provider_user_id:
        return json_error("provider_user_id is required.", http_status=400)

    acct_key = ensure_account(provider, provider_user_id)
    sub = get_subscription_by_acct_key(acct_key)

    return jsonify(ok=True, acct_key=acct_key, subscription=sub), 200
