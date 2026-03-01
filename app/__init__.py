# app/__init__.py
from __future__ import annotations

import os
import uuid
from typing import Any, Dict, Optional, Tuple, List, Union

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
    # Cookie auth mode requires explicit origins + credentials
    if _truthy(os.getenv("COOKIE_AUTH_ENABLED", "")):
        return True
    if _truthy(os.getenv("WEB_AUTH_ENABLED", "")) and os.getenv("WEB_AUTH_COOKIE_SAMESITE"):
        return True
    return False


def _parse_origins(
    origins_raw: str, *, cookie_mode: bool
) -> Tuple[Union[str, List[str]], bool, Optional[str]]:
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


def _import_attr(dotted: str, attr: str):
    try:
        mod = __import__(dotted, fromlist=[attr])
        return getattr(mod, attr), None
    except Exception as e:
        return None, f"{dotted}:{attr} -> {repr(e)}"


def _safe_get_env_bool(name: str) -> bool:
    return _truthy(os.getenv(name, ""))


def create_app() -> Flask:
    app = Flask(__name__)

    api_prefix = _normalize_api_prefix(API_PREFIX)

    # ---------- CORS ----------
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
            "X-Request-Id",
        ],
        expose_headers=["Set-Cookie", "X-Request-Id"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        max_age=86400,
    )

    # ---------- Request id ----------
    @app.before_request
    def _assign_request_id():
        rid = (request.headers.get("X-Request-Id") or "").strip()
        if not rid:
            rid = str(uuid.uuid4())
        request.environ["REQUEST_ID"] = rid

    @app.after_request
    def _attach_request_id(resp):
        rid = str(request.environ.get("REQUEST_ID") or "")
        if rid:
            resp.headers["X-Request-Id"] = rid
        return resp

    def _rid() -> str:
        return str(request.environ.get("REQUEST_ID") or "")

    def _debug_enabled() -> bool:
        return (request.headers.get("X-Debug") or "").strip() == "1"

    # ---------- Boot report ----------
    boot: Dict[str, Any] = {
        "api_prefix": api_prefix,
        "cookie_mode": cookie_mode,
        "cors": {"origins": origins, "supports_credentials": supports_credentials},
        "strict": (os.getenv("STRICT_BLUEPRINTS", "1").strip() != "0"),
        "debug_routes_enabled": _safe_get_env_bool("ENABLE_DEBUG_ROUTES"),
        "registered": [],
        "failed": [],
    }
    strict = bool(boot["strict"])

    def _register_bp(
        dotted: str,
        attr: str = "bp",
        *,
        alias_name: Optional[str] = None,
        required: bool = True,
        url_prefix: Optional[str] = api_prefix,
    ):
        obj, err = _import_attr(dotted, attr)
        entry: Dict[str, Any] = {
            "module": dotted,
            "attr": attr,
            "alias_name": alias_name or dotted.split(".")[-1],
            "url_prefix": url_prefix,
            "required": required,
        }

        if obj is None:
            entry["error"] = err
            boot["failed"].append(entry)
            if required and strict:
                raise RuntimeError(f"[boot] REQUIRED blueprint import failed: {err}")
            return

        bp_name = getattr(obj, "name", None) or f"{dotted}:{attr}"

        # prevent duplicate blueprint names
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

        if url_prefix is not None:
            app.register_blueprint(obj, url_prefix=url_prefix)
        else:
            app.register_blueprint(obj)

        entry["bp_name"] = bp_name
        boot["registered"].append(entry)

    # ---------- REQUIRED routes ----------
    required_modules = [
        "app.routes.health",
        "app.routes.accounts",
        "app.routes.subscriptions",
        "app.routes.ask",
        "app.routes.web",          # compat: /api/web/ask etc.
        "app.routes.webhooks",
        "app.routes.plans",
        "app.routes.billing",      # ✅ REQUIRED (your Paystack flow lives here)
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

    # ---------- OPTIONAL routes ----------
    # ✅ Paystack module file was deleted, so DO NOT register it here.
    # _register_bp("app.routes.paystack", "paystack_bp", alias_name="paystack", required=False, url_prefix=api_prefix)
    # _register_bp("app.routes.paystack_webhook", "bp", alias_name="paystack_webhook", required=False, url_prefix=api_prefix)

    _register_bp("app.routes.cron", "bp", alias_name="cron", required=False, url_prefix=api_prefix)

    # ---------- DEBUG routes ----------
    if _safe_get_env_bool("ENABLE_DEBUG_ROUTES"):
        _register_bp("app.routes._debug", "bp", required=False, url_prefix=api_prefix)
        _register_bp("app.routes.debug_routes", "bp", required=False, url_prefix=api_prefix)

    # ---------- Boot report endpoint ----------
    @app.get(f"{api_prefix}/_boot")
    def boot_report():
        admin_key_set = bool((os.getenv("ADMIN_KEY") or "").strip())
        return jsonify(
            {
                "ok": True,
                "request_id": _rid(),
                "admin_key_set": admin_key_set,
                "boot": boot,
            }
        ), 200

    # ---------- Runtime diagnostics ----------
    @app.get(f"{api_prefix}/_diag")
    def runtime_diag():
        hints: List[str] = []

        cron_registered = any((r.get("alias_name") == "cron") for r in boot.get("registered", []))
        if not cron_registered:
            hints.append("Cron blueprint is NOT registered. Confirm app/routes/cron.py exists and exports bp = Blueprint(...).")

        if cookie_mode and origins == "*":
            hints.append("COOKIE_MODE is enabled but CORS origins are '*'. Use explicit origins when cookies are used.")

        if not (os.getenv("SUPABASE_URL") or "").strip():
            hints.append("SUPABASE_URL is missing -> Supabase RPC/table calls will fail.")
        if not (os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY") or "").strip():
            hints.append("SUPABASE service key is missing -> RPC/table calls may fail.")

        if not (os.getenv("PAYSTACK_WEBHOOK_SECRET") or "").strip():
            hints.append("PAYSTACK_WEBHOOK_SECRET is missing. Paystack signature verification will fail for /api/billing/webhook.")

        env_view = {
            "ADMIN_KEY_SET": bool((os.getenv("ADMIN_KEY") or "").strip()),
            "API_PREFIX": api_prefix,
            "COOKIE_MODE": cookie_mode,
            "CORS_ORIGINS_MODE": ("*" if origins == "*" else "list"),
            "ENABLE_DEBUG_ROUTES": _safe_get_env_bool("ENABLE_DEBUG_ROUTES"),
            "STRICT_BLUEPRINTS": strict,
            "SUPPORTS_CREDENTIALS": supports_credentials,
            "WEB_AUTH_ENABLED": _safe_get_env_bool("WEB_AUTH_ENABLED"),
        }

        return jsonify({"ok": True, "request_id": _rid(), "env": env_view, "hints": hints}), 200

    # ---------- Preflight safety net ----------
    @app.route(f"{api_prefix}/<path:_any>", methods=["OPTIONS"])
    def _api_preflight(_any: str):
        return ("", 204)

    # ---------- Global error handler (always JSON) ----------
    @app.errorhandler(Exception)
    def _handle_any_error(e: Exception):
        status = getattr(e, "code", 500)
        msg = str(e) or type(e).__name__

        out: Dict[str, Any] = {
            "ok": False,
            "request_id": _rid(),
            "error": type(e).__name__,
            "message": msg[:800],
        }

        if _debug_enabled():
            import traceback as _tb

            out["debug"] = {
                "path": request.path,
                "method": request.method,
                "content_type": request.content_type,
            }
            out["traceback"] = _tb.format_exc(limit=60)

        return jsonify(out), status

    return app
