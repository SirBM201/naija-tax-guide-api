# app/__init__.py
from __future__ import annotations

import os
import traceback
import uuid
from typing import Any, Dict, List, Optional, Tuple, Union

from flask import Flask, jsonify, request
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
    Cookie auth should be explicitly enabled; otherwise you can accidentally
    require credentialed CORS and break public API usage.
    """
    if _truthy(os.getenv("COOKIE_AUTH_ENABLED", "")):
        return True
    # common pattern: WEB_AUTH_ENABLED + explicit SAMESITE implies cookie auth
    if _truthy(os.getenv("WEB_AUTH_ENABLED", "")) and os.getenv("WEB_AUTH_COOKIE_SAMESITE"):
        return True
    return False


def _parse_origins(
    origins_raw: str, *, cookie_mode: bool
) -> Tuple[Union[str, List[str]], bool, Optional[str]]:
    """
    Returns: (origins, supports_credentials, error_message)
    """
    raw = (origins_raw or "").strip()

    # no origins specified
    if not raw:
        if cookie_mode:
            return [], True, "CORS_ORIGINS is empty but cookie auth requires explicit origins."
        return "*", False, None

    # wildcard origins
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

    # non-cookie mode (bearer tokens) can be non-credentialed
    return origins, False, None


def _import_attr(dotted: str, attr: str):
    try:
        mod = __import__(dotted, fromlist=[attr])
        return getattr(mod, attr), None
    except Exception as e:
        return None, f"{dotted}:{attr} -> {repr(e)}"


def create_app() -> Flask:
    app = Flask(__name__)

    # ------------------------------------------------------------
    # API prefix + CORS
    # ------------------------------------------------------------
    api_prefix = _normalize_api_prefix(API_PREFIX)

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

    # ------------------------------------------------------------
    # Boot report tracking
    # ------------------------------------------------------------
    boot: Dict[str, Any] = {
        "api_prefix": api_prefix,
        "cookie_mode": cookie_mode,
        "cors": {"origins": origins, "supports_credentials": supports_credentials},
        "strict": (os.getenv("STRICT_BLUEPRINTS", "1").strip() != "0"),
        "debug_routes_enabled": _truthy(os.getenv("ENABLE_DEBUG_ROUTES", "0")),
        "registered": [],
        "failed": [],
    }
    strict = bool(boot["strict"])

    def _register_bp(
        dotted: str,
        attr: str = "bp",
        required: bool = True,
        url_prefix: Optional[str] = api_prefix,
    ):
        obj, err = _import_attr(dotted, attr)
        entry = {
            "module": dotted,
            "attr": attr,
            "required": required,
            "url_prefix": url_prefix,
        }

        if obj is None:
            entry["error"] = err
            boot["failed"].append(entry)
            if required and strict:
                raise RuntimeError(f"[boot] REQUIRED blueprint import failed: {err}")
            return

        bp_name = getattr(obj, "name", None) or f"{dotted}:{attr}"

        # ensure we don’t double-register same blueprint name
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

        if url_prefix is None:
            app.register_blueprint(obj)
        else:
            app.register_blueprint(obj, url_prefix=url_prefix)

        entry["bp_name"] = bp_name
        boot["registered"].append(entry)

    # ------------------------------------------------------------
    # Register routes
    # ------------------------------------------------------------
    # REQUIRED routes (app must fail if these don’t load)
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

    # OPTIONAL routes (do not fail boot if these aren’t present)
    _register_bp("app.routes.paystack", "bp", required=False, url_prefix=api_prefix)
    _register_bp("app.routes.paystack", "paystack_bp", required=False, url_prefix=api_prefix)
    _register_bp("app.routes.paystack_webhook", "bp", required=False, url_prefix=api_prefix)

    # Cron is usually mounted WITHOUT api_prefix inside that module (it should define /api/internal/... itself)
    _register_bp("app.routes.cron", "bp", required=False, url_prefix=None)

    # DEBUG routes (opt-in)
    if _truthy(os.getenv("ENABLE_DEBUG_ROUTES", "0")):
        _register_bp("app.routes._debug", "bp", required=False, url_prefix=api_prefix)
        _register_bp("app.routes.debug_routes", "bp", required=False, url_prefix=api_prefix)

    # ------------------------------------------------------------
    # Boot endpoint (always available)
    # ------------------------------------------------------------
    @app.get(f"{api_prefix}/_boot")
    def boot_report():
        request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        admin_key_set = bool(os.getenv("ADMIN_KEY", "").strip())
        return jsonify(
            {
                "ok": True,
                "request_id": request_id,
                "admin_key_set": admin_key_set,
                "boot": boot,
            }
        ), 200

    # ------------------------------------------------------------
    # Global error handler (short in prod, rich when X-Debug: 1)
    # ------------------------------------------------------------
    @app.errorhandler(Exception)
    def _handle_any_error(e: Exception):
        status = getattr(e, "code", 500)
        msg = str(e) or type(e).__name__
        request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())

        debug_on = (request.headers.get("X-Debug") or "").strip() == "1"

        out: Dict[str, Any] = {
            "ok": False,
            "request_id": request_id,
            "error": type(e).__name__,
            "message": msg[:400],
        }

        if debug_on:
            out["debug"] = {
                "path": request.path,
                "method": request.method,
                "query": request.query_string.decode("utf-8", errors="ignore"),
                "remote_addr": request.headers.get("X-Forwarded-For") or request.remote_addr,
                # keep traceback limited but useful
                "trace": traceback.format_exc(limit=12),
            }

        return jsonify(out), status

    return app
