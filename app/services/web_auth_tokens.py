# app/services/web_auth_tokens.py
from __future__ import annotations

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from typing import Optional, Dict, Any

from ..core.config import APP_SECRET_KEY, ACCESS_TOKEN_TTL_SECONDS

if not APP_SECRET_KEY:
    raise RuntimeError("Missing APP_SECRET_KEY (or SECRET_KEY)")

_serializer = URLSafeTimedSerializer(APP_SECRET_KEY, salt="web-auth-token")

def issue_access_token(payload: Dict[str, Any]) -> str:
    # payload should include at least: {"account_id": "..."}
    return _serializer.dumps(payload)

def verify_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        data = _serializer.loads(token, max_age=ACCESS_TOKEN_TTL_SECONDS)
        if not isinstance(data, dict):
            return None
        return data
    except (SignatureExpired, BadSignature):
        return None
    except Exception:
        return None
