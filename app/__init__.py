# app/__init__.py
from __future__ import annotations

import os
import traceback
from typing import Any, Dict, List, Optional, Tuple, Union

from flask import Flask, jsonify, request
from flask_cors import CORS

from app.core.config import API_PREFIX, CORS_ORIGINS


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
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
    Otherwise you can accidentally force credentialed CORS and break clients.
    """
    if _truthy(os.getenv("COOKIE_AUTH_ENABLED", "")):
        return True
    # Back-compat: if web auth is enabled and cookie samesite is set, treat as cookie mode.
    if _truthy(os.getenv("WEB_AUTH_ENABLED", "")) and os.getenv("WEB_AUTH_COOKIE_SAMESITE"):
        return True
    return False


def _parse_origins(
    origins_raw: str, *, cookie_mode: bool
) -> Tuple[Union[str, List[str]], bool, Optional[str]]:
    raw = (origins_raw or "").strip()

    # No origins provided
    if not raw:
        if cookie_mode:
            return [], True, "CORS_ORIGINS is empty but cookie auth requires explicit origins."
        return "*", False, None

    # Wildcard origin
    if raw == "*":
        if cookie_mode:
            return [], True, "CORS_ORIGINS='*' is not allowed with cookie auth. Use explicit comma-separated origins."
        return "*", False, None

    # Comma-separated list
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    if not origins:
        if cookie_mode:
            return [], True, "CORS_ORIGINS parsed empty but cookie auth requires explicit origins."
        return "*", False, None

    # If cookie mode, we must allow credentials
    if cookie_mode:
        return origins, True, None

    # Non-cookie mode: explicit list is OK, but credentials can be off
    return origins, False, None


def _import_attr(dotted: str, attr: str):
    try:
        mod = __import__(dotted, fromlist=[attr])
        return getattr(mod, attr), None
    except Exception as e:
        return None, f"{dotted}:{attr} -> {repr(e)}"


# ------------------------------------------------------------
# App factory
# ------------------------------------------------------------
def create_app() -> Flask:
    app = Flask(__name__)

    # IMPORTANT: admin key for internal routes (cron/debug)
    # Set this in Koyeb env: ADMIN_KEY=...
    app.config["ADMIN_KEY"] = (os.getenv("ADMIN_KEY", "") or "").strip()

    api_prefix = _normalize_api_prefix(API_PREFIX)

    # -------------------------
    # CORS
    # -------------------------
    cookie_mode = _cookie_mode_enabled()
    origins, supports_credentials, cors_err = _parse_origins(CORS_ORIGINS, cookie_mode=cookie_mode)
    if cors_err:
        raise RuntimeError(f"[CORS] {cors_err}")

    CORS(
        app,
        resources={rf"{api_prefix}/*": {"origins": origins}},
        supports_credentials=supports_credentials,
        allow_headers=[
            "Content-Type",
            "Authorization",
            "X-Auth-Token",
            "X-Requested-With",
            "X-Admin-Key",
            "X-Debug",
        ],
        expose_headers=["Set-Cookie"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        max_age=86400,
    )

    # -------------------------
    # Boot report (debug visibility)
    # -------------------------
    boot: Dict[str, Any] = {
        "api_prefix": api_prefix,
        "cookie_mode": cookie_mode,
        "cors": {"origins": origins, "supports_credentials": supports_credentials},
        "strict": (os.getenv("STRICT_BLUEPRINTS", "1").strip() != "0"),
        "debug_routes_enabled": _truthy(os.getenv("ENABLE_DEBUG_ROUTES", "0")),
        "admin_key_set": bool(app.config["ADMIN_KEY"]),
        "registered": [],
        "failed": [],
    }
    strict = boot["strict"]

    def _register_bp(
        dotted: str,
        attr: str = "bp",
        required: bool = True,
        url_prefix: Optional[str] = api_prefix,
    ):
        obj, err = _import_attr(dotted, attr)
        entry: Dict[str, Any] = {"module": dotted, "attr": attr, "url_prefix": url_prefix, "required": required}

        if obj is None:
            entry["error"] = err
            boot["failed"].append(entry)
            if required and strict:
                raise RuntimeError(f"[boot] REQUIRED blueprint import failed: {err}")
            return

        # Prefer blueprint's actual .name, otherwise derive stable name
        bp_name = getattr(obj, "name", None) or f"{dotted}:{attr}"

        # Track duplicates by blueprint NAME (Flask requires unique names)
        if not hasattr(app, "_bp_names"):
            app._bp_names = set()  # type: ignore[attr-defined]

        if bp_name in app._bp_names:  # type: ignore[attr-defined]
            msg = f"[boot] Duplicate blueprint name detected: {bp_name} from {dotted}:{attr}"
            entry["error"] = msg
            boot["failed"].append(entry)
            if required and strict:
                raise RuntimeError(msg)
            return

        app._bp_names.add(bp_name)  # type: ignore[attr-defined]

        # Register
        if url_prefix:
            app.register_blueprint(obj, url_prefix=url_prefix)
        else:
            app.register_blueprint(obj)

        entry["bp_name"] = bp_name
        boot["registered"].append(entry)

    # ------------------------------------------------------------
    # REQUIRED routes (must exist)
    # ------------------------------------------------------------
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
    ]
    for dotted in required_modules:
        _register_bp(dotted, "bp", required=True, url_prefix=api_prefix)

    # ------------------------------------------------------------
    # OPTIONAL routes (may or may not exist)
    # IMPORTANT: Do NOT register the same module twice (this caused your paystack duplication)
    # ------------------------------------------------------------
    # Paystack (choose ONE bp only). Keep these commented unless your project actually has them.
    _register_bp("app.routes.paystack", "bp", required=False, url_prefix=api_prefix)
    _register_bp("app.routes.paystack_webhook", "bp", required=False, url_prefix=api_prefix)

    # Internal cron routes (RECOMMENDED)
    _register_bp("app.routes.internal_cron", "bp", required=False, url_prefix=api_prefix)

    # Debug routes (optional)
    if _truthy(os.getenv("ENABLE_DEBUG_ROUTES", "0")):
        _register_bp("app.routes._debug", "bp", required=False, url_prefix=api_prefix)
        _register_bp("app.routes.debug_routes", "bp", required=False, url_prefix=api_prefix)

    # ------------------------------------------------------------
    # Boot report endpoint
    # ------------------------------------------------------------
    @app.get(f"{api_prefix}/_boot")
    def boot_report():
        return jsonify({"ok": True, "boot": boot}), 200

    # ------------------------------------------------------------
    # Global error handler (Debugger exposer)
    # - Use header: X-Debug: 1 to see trace and extra context
    # ------------------------------------------------------------
    @app.errorhandler(Exception)
    def _handle_any_error(e: Exception):
        status = getattr(e, "code", 500)  # HTTPException has .code
        msg = str(e) or type(e).__name__

        debug_on = (request.headers.get("X-Debug") or "").strip() == "1"
        out: Dict[str, Any] = {
            "ok": False,
            "error": type(e).__name__,
            "message": msg[:500],
        }

        if debug_on:
            out["debug"] = {
                "path": request.path,
                "method": request.method,
                "query": request.query_string.decode("utf-8", errors="ignore"),
                "remote_addr": request.remote_addr,
            }
            out["trace"] = traceback.format_exc()

        return jsonify(out), status

    return app
