# app/db/supabase_rest.py
from typing import Any, Dict, List, Optional
import requests

from app.core.config import SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY


def _headers() -> Dict[str, str]:
    key = SUPABASE_SERVICE_ROLE_KEY
    return {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }


def sb_get(path: str, params: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        return []
    url = f"{SUPABASE_URL}/rest/v1/{path}"
    r = requests.get(url, headers=_headers(), params=params, timeout=20)
    if r.status_code >= 400:
        return []
    return r.json() if r.content else []


def sb_post(path: str, json: Any) -> bool:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        return False
    url = f"{SUPABASE_URL}/rest/v1/{path}"
    r = requests.post(url, headers=_headers(), json=json, timeout=20)
    return r.status_code < 400


def sb_patch(path: str, json: Any, params: Optional[Dict[str, str]] = None) -> bool:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        return False
    url = f"{SUPABASE_URL}/rest/v1/{path}"
    r = requests.patch(url, headers=_headers(), json=json, params=params, timeout=20)
    return r.status_code < 400


def sb_rpc(fn: str, json: Any) -> List[Dict[str, Any]]:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        return []
    url = f"{SUPABASE_URL}/rest/v1/rpc/{fn}"
    r = requests.post(url, headers=_headers(), json=json, timeout=20)
    if r.status_code >= 400:
        return []
    return r.json() if r.content else []
