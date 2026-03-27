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


def _normalize_joined_prefix(base: Optional[str], child: Optional[str]) -> Optional[str]:
    base = (base or "").strip()
    child = (child or "").strip()

    if not base and not child:
        return None

    if base and not base.startswith("/"):
        base = "/" + base
    if child and not child.startswith("/"):
        child = "/" + child

    base = base.rstrip("/")
    child = child.rstrip("/")

    if not base:
        return child or None
    if not child:
        return base or None

    if child == "/":
        return base

    return f"{base}{child}"


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _cookie_mode_enabled() -> bool:
    if _truthy(os.getenv("COOKIE_AUTH_ENABLED", "1")):
        return True
    if _truthy(os.getenv("WEB_AUTH_ENABLED", "")) and (os.getenv("COOKIE_SAMESITE") or "").strip():
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

    cookie_mode = _cookie_mode_enabled()
    origins, supports_credentials, cors_err = _parse_origins(
        CORS_ORIGINS, cookie_mode=cookie_mode
    )
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
            "X-Seed-Token",
        ],
        expose_headers=["Set-Cookie", "X-Request-Id"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        max_age=86400,
        vary_header=True,
    )

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

        if request.path.startswith(f"{api_prefix}/web/auth/"):
            resp.headers["Cache-Control"] = "no-store"

        return resp

    def _rid() -> str:
        return str(request.environ.get("REQUEST_ID") or "")

    boot: Dict[str, Any] = {
        "api_prefix": api_prefix,
        "cookie_mode": cookie_mode,
        "cors": {
            "origins": origins,
            "supports_credentials": supports_credentials,
        },
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
            "required": required,
        }

        if obj is None:
            entry["error"] = err
            boot["failed"].append(entry)
            if required and strict:
                raise RuntimeError(f"[boot] REQUIRED blueprint import failed: {err}")
            return

        bp_name = getattr(obj, "name", None) or f"{dotted}:{attr}"

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

        bp_internal_prefix = getattr(obj, "url_prefix", None)
        effective_prefix = _normalize_joined_prefix(url_prefix, bp_internal_prefix)

        if effective_prefix is not None:
            app.register_blueprint(obj, url_prefix=effective_prefix)
        else:
            app.register_blueprint(obj)

        entry["bp_name"] = bp_name
        entry["bp_internal_prefix"] = bp_internal_prefix
        entry["url_prefix"] = effective_prefix
        boot["registered"].append(entry)

    required_modules = [
        "app.routes.health",
        "app.routes.accounts",
        "app.routes.subscriptions",
        "app.routes.ask",
        "app.routes.web",
        "app.routes.webhooks",
        "app.routes.plans",
        "app.routes.billing",
        "app.routes.link_tokens",
        "app.routes.admin_link_tokens",
        "app.routes.accounts_admin",
        "app.routes.meta",
        "app.routes.email_link",
        "app.routes.web_auth",
        "app.routes.web_session",
        "app.routes.feedback",
        "app.routes.admin_semantic",
        "app.routes.referrals",
        "app.routes.paystack_webhook",
    ]
    for dotted in required_modules:
        _register_bp(dotted, "bp", required=True, url_prefix=api_prefix)

    _register_bp("app.routes.cron", "bp", alias_name="cron", required=False, url_prefix=api_prefix)
    _register_bp("app.routes.support", "bp", alias_name="support", required=False, url_prefix=api_prefix)
    _register_bp("app.routes.history", "bp", alias_name="history", required=False, url_prefix=api_prefix)
    _register_bp("app.routes.dev_tools", "bp", alias_name="dev_tools", required=False, url_prefix=api_prefix)

    _register_bp("app.routes.telegram", "bp", alias_name="telegram", required=False, url_prefix=api_prefix)
    _register_bp("app.routes.whatsapp", "bp", alias_name="whatsapp", required=False, url_prefix=api_prefix)

    _register_bp("app.routes.entry", "bp", alias_name="entry", required=False, url_prefix=api_prefix)
    _register_bp("app.routes.channel_access", "bp", alias_name="channel_access", required=False, url_prefix=api_prefix)
    _register_bp("app.routes.channel_profile", "bp", alias_name="channel_profile", required=False, url_prefix=api_prefix)

    if _safe_get_env_bool("ENABLE_DEBUG_ROUTES"):
        _register_bp("app.routes._debug", "bp", required=False, url_prefix=api_prefix)
        _register_bp("app.routes.debug_routes", "bp", required=False, url_prefix=api_prefix)

    @app.get(f"{api_prefix}/_boot")
    def boot_report():
        admin_key_set = bool((os.getenv("ADMIN_KEY") or "").strip())
        seed_token_set = bool((os.getenv("SEED_TAX_TOKEN") or "").strip())
        return jsonify(
            {
                "ok": True,
                "request_id": _rid(),
                "admin_key_set": admin_key_set,
                "seed_token_set": seed_token_set,
                "boot": boot,
            }
        ), 200

    @app.get(f"{api_prefix}/_diag")
    def runtime_diag():
        hints: List[str] = []

        cron_registered = any((r.get("alias_name") == "cron") for r in boot.get("registered", []))
        if not cron_registered:
            hints.append(
                "Cron blueprint is NOT registered. Confirm app/routes/cron.py exists and exports bp = Blueprint(...)."
            )

        referrals_registered = any((r.get("alias_name") == "referrals") for r in boot.get("registered", []))
        if not referrals_registered:
            hints.append(
                "Referrals blueprint is NOT registered. Confirm app/routes/referrals.py exists and exports bp = Blueprint(...)."
            )

        paystack_webhook_registered = any((r.get("alias_name") == "paystack_webhook") for r in boot.get("registered", []))
        if not paystack_webhook_registered:
            hints.append(
                "Paystack webhook blueprint is NOT registered. Confirm app/routes/paystack_webhook.py exists and exports bp = Blueprint(...)."
            )

        telegram_registered = any((r.get("alias_name") == "telegram") for r in boot.get("registered", []))
        if not telegram_registered:
            hints.append(
                "Telegram blueprint is NOT registered. Confirm app/routes/telegram.py exists and exports bp = Blueprint(...)."
            )

        whatsapp_registered = any((r.get("alias_name") == "whatsapp") for r in boot.get("registered", []))
        if not whatsapp_registered:
            hints.append(
                "WhatsApp blueprint is NOT registered. Confirm app/routes/whatsapp.py exists and exports bp = Blueprint(...)."
            )

        link_tokens_registered = any((r.get("alias_name") == "link_tokens") for r in boot.get("registered", []))
        if not link_tokens_registered:
            hints.append(
                "Link tokens blueprint is NOT registered. Confirm app/routes/link_tokens.py exists and exports bp = Blueprint(...)."
            )

        entry_registered = any((r.get("alias_name") == "entry") for r in boot.get("registered", []))
        if not entry_registered:
            hints.append(
                "Entry blueprint is NOT registered. Confirm app/routes/entry.py exists and exports bp = Blueprint(...)."
            )

        channel_access_registered = any((r.get("alias_name") == "channel_access") for r in boot.get("registered", []))
        if not channel_access_registered:
            hints.append(
                "Channel access blueprint is NOT registered. Confirm app/routes/channel_access.py exists and exports bp = Blueprint(...)."
            )

        channel_profile_registered = any((r.get("alias_name") == "channel_profile") for r in boot.get("registered", []))
        if not channel_profile_registered:
            hints.append(
                "Channel profile blueprint is NOT registered. Confirm app/routes/channel_profile.py exists and exports bp = Blueprint(...)."
            )

        if cookie_mode and origins == "*":
            hints.append(
                "COOKIE_MODE is enabled but CORS origins are '*'. Use explicit origins when cookies are used."
            )

        if cookie_mode and (isinstance(origins, list) and not origins):
            hints.append(
                "COOKIE_MODE is enabled but parsed origins list is empty. Set CORS_ORIGINS to your frontend URL(s)."
            )

        return jsonify(
            {
                "ok": True,
                "request_id": _rid(),
                "boot": boot,
                "hints": hints,
            }
        ), 200

    return app
