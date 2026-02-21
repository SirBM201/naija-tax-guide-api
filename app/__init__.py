# app/__init__.py
from __future__ import annotations

import os
from typing import Any, Dict, Optional, Tuple, List, Union

from flask import Flask, jsonify
from flask_cors import CORS

from app.core.config import API_PREFIX, CORS_ORIGINS


def _normalize_api_prefix(v: str) -> str:
    v = (v or "").strip()
    if not v:
        return "/api"
    if not v.startswith("/"):
        v = "/" + v
    return v.rstrip("/")


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _cookie_mode_enabled() -> bool:
    """
    Cookie auth should be explicitly enabled.
    Otherwise you'll accidentally force credentialed CORS and break '*' origins.
    """
    # Preferred explicit flag
    if _truthy(os.getenv("COOKIE_AUTH_ENABLED", "")):
        return True

    # Backwards compat: allow enabling via WEB_AUTH_ENABLED + explicit cookie samesite/secure
    if _truthy(os.getenv("WEB_AUTH_ENABLED", "")) and os.getenv("WEB_AUTH_COOKIE_SAMESITE"):
        return True

    return False


def _parse_origins(origins_raw: str, *, cookie_mode: bool) -> Tuple[Union[str, List[str]], bool, Optional[str]]:
    """
    Returns (origins, supports_credentials, error_message_if_any)

    IMPORTANT:
      - If cookie_mode=True, origins MUST be an explicit list, not '*'
      - supports_credentials must be True for cookies
    """
    raw = (origins_raw or "").strip()

    if not raw:
        if cookie_mode:
            return [], True, "CORS_ORIGINS is empty but cookie auth requires explicit origins."
        return "*", False, None

    if raw == "*":
        if cookie_mode:
            return [], True, "CORS_ORIGINS='*' is not allowed with cookie auth. Use explicit comma-separated origins."
        return "*", False, None

    origins = [o.strip() for o in raw.split(",") if o.strip()]
    if not origins:
        if cookie_mode:
            return [], True, "CORS_ORIGINS parsed empty but cookie auth requires explicit origins."
        return "*", False, None

    if cookie_mode:
        return origins, True, None

    return origins, False, None


def _import_attr(dotted: str, attr: str) -> Tuple[Optional[Any], Optional[str]]:
    try:
        mod = __import__(dotted, fromlist=[attr])
        obj = getattr(mod, attr)
        return obj, None
    except Exception as e:
        return None, f"{dotted}:{attr} -> {repr(e)}"


def create_app() -> Flask:
    app = Flask(__name__)

    api_prefix = _normalize_api_prefix(API_PREFIX)

    cookie_mode = _cookie_mode_enabled()
    origins, supports_credentials, cors_err = _parse_origins(CORS_ORIGINS, cookie_mode=cookie_mode)

    if cors_err:
        raise RuntimeError(f"[CORS] {cors_err}")

    CORS(
        app,
        resources={rf"{api_prefix}/*": {"origins": origins}},
        supports_credentials=supports_credentials,
        allow_headers=["Content-Type", "Authorization", "X-Auth-Token", "X-Requested-With"],
        expose_headers=["Set-Cookie"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        max_age=86400,
    )

    boot: Dict[str, Any] = {
        "api_prefix": api_prefix,
        "cookie_mode": cookie_mode,
        "cors": {"origins": origins, "supports_credentials": supports_credentials},
        "required": [],
        "optional": [],
        "errors": [],
    }

    strict = (os.getenv("STRICT_BLUEPRINTS", "1").strip() != "0")

    def _register_bp(dotted: str, attr: str = "bp", required: bool = True, url_prefix: Optional[str] = api_prefix):
        obj, err = _import_attr(dotted, attr)
        entry = {"module": dotted, "attr": attr, "registered": False, "url_prefix": url_prefix, "error": err}

        if obj is None:
            (boot["required"] if required else boot["optional"]).append(entry)
            if err:
                boot["errors"].append(entry)
            if required and strict:
                raise RuntimeError(f"[boot] REQUIRED blueprint import failed: {err}")
            return

        bp_name = getattr(obj, "name", None) or f"{dotted}:{attr}"

        if not hasattr(app, "_bp_names"):
            app._bp_names = set()  # type: ignore[attr-defined]

        if bp_name in app._bp_names:  # type: ignore[attr-defined]
            msg = f"[boot] Duplicate blueprint name detected: {bp_name} from {dotted}:{attr}"
            entry["error"] = msg
            boot["errors"].append(entry)
            if required and strict:
                raise RuntimeError(msg)
            return

        app._bp_names.add(bp_name)  # type: ignore[attr-defined]

        if url_prefix:
            app.register_blueprint(obj, url_prefix=url_prefix)
        else:
            app.register_blueprint(obj)

        entry["registered"] = True
        (boot["required"] if required else boot["optional"]).append(entry)

    required_modules = [
        "app.routes.health",
        "app.routes.accounts",
        "app.routes.subscriptions",
        "app.routes.ask",
        "app.routes.webhooks",
        "app.routes.plans",
        "app.routes.link_tokens",
        "app.routes.admin_link_tokens",
        "app.routes.accounts_admin",
        "app.routes.meta",
        "app.routes.email_link",
        "app.routes.web_auth",
        "app.routes.web_session",
        "app.routes.paystack_webhook",
        "app.routes.debug_routes",
    ]
    for dotted in required_modules:
        _register_bp(dotted, "bp", required=True, url_prefix=api_prefix)

    _register_bp("app.routes.paystack", "paystack_bp", required=False, url_prefix=api_prefix)
    _register_bp("app.routes.cron", "bp", required=False, url_prefix=None)

    optional_modules = [
        "app.routes.whatsapp",
        "app.routes.telegram",
        "app.routes.web_ask",
        "app.routes.web_chat",
        "app.routes.billing",
    ]
    for dotted in optional_modules:
        _register_bp(dotted, "bp", required=False, url_prefix=api_prefix)

    @app.get(f"{api_prefix}/_boot")
    def boot_report():
        return jsonify({"ok": True, "boot": boot, "strict": strict})

    return app
