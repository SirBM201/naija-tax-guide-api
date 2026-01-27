# app/__init__.py
import logging
from flask import Flask, jsonify
from flask_cors import CORS

from app.core.config import allowed_origins
from app.core.utils import init_logging, register_error_handlers


def create_app() -> Flask:
    init_logging()
    app = Flask(__name__)

    CORS(
        app,
        resources={r"/*": {"origins": allowed_origins}},
        supports_credentials=False,
        allow_headers=[
            "Content-Type",
            "x-admin-key",
            "X-Telegram-Bot-Api-Secret-Token",
            "X-Webhook-Secret",  # ✅ for WhatsApp optional extra guard
        ],
        methods=["GET", "POST", "OPTIONS"],
    )

    register_error_handlers(app)

    # Blueprints (your pattern is bp = Blueprint(...))
    from app.routes.health import bp as health_bp
    from app.routes.ask import bp as ask_bp
    from app.routes.paystack_routes import bp as paystack_bp
    from app.routes.telegram_routes import bp as telegram_bp
    from app.routes.cron import bp as cron_bp
    from app.routes.subscription_routes import bp as subscription_bp
    from app.routes.whatsapp_routes import bp as whatsapp_bp  # ✅ NEW

    app.register_blueprint(health_bp)
    app.register_blueprint(ask_bp)
    app.register_blueprint(paystack_bp)
    app.register_blueprint(telegram_bp)
    app.register_blueprint(cron_bp)
    app.register_blueprint(subscription_bp)
    app.register_blueprint(whatsapp_bp)  # ✅ NEW

    @app.get("/")
    def root():
        return jsonify({"ok": True, "service": "naija-tax-guide-api"})

    # Helpful: log registered routes on boot (shows in Koyeb logs)
    try:
        for rule in sorted(app.url_map.iter_rules(), key=lambda r: str(r)):
            if rule.endpoint == "static":
                continue
            logging.info("ROUTE %s %s -> %s", sorted(rule.methods), rule, rule.endpoint)
    except Exception:
        pass

    return app
