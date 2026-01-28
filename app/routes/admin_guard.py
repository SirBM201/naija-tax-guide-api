import os
from flask import request

COOKIE_NAME = "ntg_admin"

def admin_expected_key() -> str:
    return os.getenv("ADMIN_ACCESS_KEY", "").strip()

def is_admin_authed() -> bool:
    expected = admin_expected_key()
    if not expected:
        return False
    return request.cookies.get(COOKIE_NAME, "") == expected
