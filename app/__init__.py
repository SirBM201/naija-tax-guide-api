# app/__init__.py
from __future__ import annotations

from flask import Flask
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


def _safe_import_bp(dotted: str, attr: str = "bp"):
    """
    Import a blueprint safely.
    If missing or import fails, return None so the server still boots.
    """
    try:
        mod = __import__(dotted, fromlist=[attr])
        return getattr(mod, attr)
    except Exception as e:
        # Optional: print for easier debugging on Koyeb logs
        print(f"[boot] optional import failed: {dotted}:{attr} -> {e}")
        return None


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

    # -----------------------------
    # REQUIRED / CORE BLUEPRINTS
    # -----------------------------
    for dotted in [
        "app.routes.health",
        "app.routes.accounts",
        "app.routes.subscriptions",
        "app.routes.ask",
        "app.routes.webhooks",
        "app.routes.plans",
        "app.routes.link_tokens",
        "app.routes.whatsapp",
        "app.routes.admin_link_tokens",
        "app.routes.debug_routes",
        "app.routes.accounts_admin",
        "app.routes.meta",
        "app.routes.email_link",
        "app.routes.web_auth",
        "app.routes.web_session",
        "app.routes.paystack_webhook",
    ]:
        bp = _safe_import_bp(dotted, "bp")
        if bp:
            app.register_blueprint(bp, url_prefix=api_prefix)

    # paystack_bp is named differently in your project
    paystack_bp = _safe_import_bp("app.routes.paystack", "paystack_bp")
    if paystack_bp:
        app.register_blueprint(paystack_bp, url_prefix=api_prefix)

    # Cron (no /api prefix usually)
    cron_bp = _safe_import_bp("app.routes.cron", "bp")
    if cron_bp:
        app.register_blueprint(cron_bp)

    # -----------------------------
    # OPTIONAL BLUEPRINTS
    # -----------------------------
    for dotted in [
        "app.routes.telegram",
        "app.routes.web_ask",
        "app.routes.web_chat",
        "app.routes.billing",
    ]:
        bp = _safe_import_bp(dotted, "bp")
        if bp:
            app.register_blueprint(bp, url_prefix=api_prefix)

    return app
