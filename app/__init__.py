# app/__init__.py
from __future__ import annotations

import os
from typing import Any, Dict, Optional, Tuple, List

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


def _parse_origins(origins_raw: str):
    raw = (origins_raw or "").strip()
    if not raw:
        return "*", False
    if raw == "*":
        return "*", False
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    return origins, True


def _import_attr(dotted: str, attr: str) -> Tuple[Optional[Any], Optional[str]]:
    """
    Import module.attr safely. Returns (obj, error_string).
    """
    try:
        mod = __import__(dotted, fromlist=[attr])
        obj = getattr(mod, attr)
        return obj, None
    except Exception as e:
        return None, f"{dotted}:{attr} -> {repr(e)}"


def create_app() -> Flask:
    app = Flask(__name__)

    api_prefix = _normalize_api_prefix(API_PREFIX)
    origins, supports_credentials = _parse_origins(CORS_ORIGINS)

    CORS(
        app,
        resources={rf"{api_prefix}/*": {"origins": origins}},
        supports_credentials=supports_credentials,
        allow_headers=["Content-Type", "Authorization"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        max_age=86400,
    )

    # ---------------------------------------
    # BOOT REPORT (so you can see import fails)
    # ---------------------------------------
    boot: Dict[str, Any] = {
        "api_prefix": api_prefix,
        "required": [],
        "optional": [],
        "errors": [],
    }

    # Strict mode: default ON in production
    # You can disable temporarily by setting STRICT_BLUEPRINTS=0
    strict = (os.getenv("STRICT_BLUEPRINTS", "1").strip() != "0")

    def _register_bp(dotted: str, attr: str = "bp", required: bool = True, url_prefix: Optional[str] = api_prefix):
        obj, err = _import_attr(dotted, attr)
        entry = {"module": dotted, "attr": attr, "registered": False, "url_prefix": url_prefix, "error": err}

        if obj is None:
            (boot["required"] if required else boot["optional"]).append(entry)
            if err:
                boot["errors"].append(entry)
            if required and strict:
                # Fail loudly so we never deploy an "empty app"
                raise RuntimeError(f"[boot] REQUIRED blueprint import failed: {err}")
            return

        # Deduplicate by blueprint name (not id)
        bp_name = getattr(obj, "name", None)
        if not bp_name:
            bp_name = f"{dotted}:{attr}"

        # Keep a set on app to avoid double registration
        if not hasattr(app, "_bp_names"):
            app._bp_names = set()  # type: ignore[attr-defined]

        if bp_name in app._bp_names:  # type: ignore[attr-defined]
            # Duplicate name => configuration bug (or double import)
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

    # ---------------------------------------
    # REQUIRED / CORE BLUEPRINTS (must exist)
    # ---------------------------------------
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

    # If your paystack routes use a different variable name
    _register_bp("app.routes.paystack", "paystack_bp", required=False, url_prefix=api_prefix)

    # Cron is usually not prefixed
    _register_bp("app.routes.cron", "bp", required=False, url_prefix=None)

    # ---------------------------------------
    # OPTIONAL BLUEPRINTS
    # ---------------------------------------
    optional_modules = [
        "app.routes.whatsapp",
        "app.routes.telegram",
        "app.routes.web_ask",
        "app.routes.web_chat",
        "app.routes.billing",
    ]

    for dotted in optional_modules:
        _register_bp(dotted, "bp", required=False, url_prefix=api_prefix)

    # ---------------------------------------
    # Boot report endpoint
    # ---------------------------------------
    @app.get(f"{api_prefix}/_boot")
    def boot_report():
        return jsonify({"ok": True, "boot": boot, "strict": strict})

    return app
