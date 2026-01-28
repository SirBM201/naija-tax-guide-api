from flask import Flask, jsonify
from flask_cors import CORS

from app.core.utils import init_logging, register_error_handlers
from app.core.config import allowed_origins


def create_app() -> Flask:
    # -------------------------------------------------
    # App bootstrap
    # -------------------------------------------------
    init_logging()
    app = Flask(__name__)

    # -------------------------------------------------
    # CORS
    # -------------------------------------------------
    CORS(
        app,
        resources={r"/*": {"origins": allowed_origins}},
        supports_credentials=True,
        allow_headers=[
            "Content-Type",
            "Authorization",
            "x-admin-key",
            "X-Telegram-Bot-Api-Secret-Token",
        ],
        methods=["GET", "POST", "OPTIONS"],
    )

    # -------------------------------------------------
    # Error handlers
    # -------------------------------------------------
    register_error_handlers(app)

    # -------------------------------------------------
    # Core / existing routes
    # -------------------------------------------------
    from app.routes.health import bp as health_bp
    from app.routes.ask import bp as ask_bp
    from app.routes.telegram_routes import bp as telegram_bp
    from app.routes.whatsapp_routes import bp as whatsapp_bp
    from app.routes.paystack_routes import bp as paystack_bp

    # -------------------------------------------------
    # NEW: security & account system routes
    # -------------------------------------------------
    from app.routes.otp_routes import bp as otp_bp
    from app.routes.merge_routes import bp as merge_bp
    from app.routes.admin_routes import bp as admin_bp

    # -------------------------------------------------
    # Register blueprints
    # -------------------------------------------------
    app.register_blueprint(health_bp)
    app.register_blueprint(ask_bp)
    app.register_blueprint(telegram_bp)
    app.register_blueprint(whatsapp_bp)
    app.register_blueprint(paystack_bp)

    app.register_blueprint(otp_bp)
    app.register_blueprint(merge_bp)
    app.register_blueprint(admin_bp)

    # -------------------------------------------------
    # Root
    # -------------------------------------------------
    @app.get("/")
    def root():
        return jsonify(ok=True, service="naija-tax-guide-api")

    # -------------------------------------------------
    # Helpful: log all routes at startup (Koyeb logs)
    # -------------------------------------------------
    try:
        for rule in sorted(app.url_map.iter_rules(), key=lambda r: str(r)):
            if rule.endpoint != "static":
                app.logger.info(
                    "ROUTE %s %s -> %s",
                    sorted(rule.methods),
                    rule,
                    rule.endpoint,
                )
    except Exception:
        pass

    return app
