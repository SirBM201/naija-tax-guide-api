# app/__init__.py
from flask import Flask, jsonify
from flask_cors import CORS

from app.core.config import allowed_origins
from app.core.utils import init_logging, register_error_handlers


def create_app() -> Flask:
    init_logging()
    app = Flask(__name__)

    # -----------------------------
    # CORS
    # -----------------------------
    CORS(
        app,
        resources={r"/*": {"origins": allowed_origins}},
        supports_credentials=False,
        allow_headers=[
            "Content-Type",
            "x-admin-key",
            "X-Telegram-Bot-Api-Secret-Token",  # IMPORTANT for Telegram webhook
        ],
        methods=["GET", "POST", "OPTIONS"],
    )

    # -----------------------------
    # Error handling & logging
    # -----------------------------
    register_error_handlers(app)

    # -----------------------------
    # Blueprints
    # -----------------------------
    from app.routes.health import bp as health_bp
    from app.routes.ask import bp as ask_bp
    from app.routes.paystack_routes import bp as paystack_bp
    from app.routes.telegram_routes import bp as telegram_bp
    from app.routes.cron import bp as cron_bp
    
    app.register_blueprint(health_bp)
    app.register_blueprint(ask_bp)
    app.register_blueprint(paystack_bp)
    app.register_blueprint(telegram_bp)
    app.register_blueprint(cron_bp)
    # -----------------------------
    # Root
    # -----------------------------
    @app.get("/")
    def root():
        return jsonify({
            "ok": True,
            "service": "naija-tax-guide-api",
        })

    return app
