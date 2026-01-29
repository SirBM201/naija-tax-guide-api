# app/__init__.py
from flask import Flask, jsonify
from flask_cors import CORS

from app.core.utils import init_logging, register_error_handlers
from app.core.config import allowed_origins

def create_app():
    init_logging()
    app = Flask(__name__)
    CORS(app, resources={r"/*": {"origins": allowed_origins}})
    register_error_handlers(app)

    from app.routes.health import bp as health_bp
    from app.routes.ask import bp as ask_bp
    from app.routes.telegram_routes import bp as telegram_bp
    from app.routes.whatsapp_routes import bp as whatsapp_bp
    from app.routes.paystack_routes import bp as paystack_bp
    from app.routes.subscription_routes import bp as subscription_bp  # NEW

    app.register_blueprint(health_bp)
    app.register_blueprint(ask_bp)
    app.register_blueprint(telegram_bp)
    app.register_blueprint(whatsapp_bp)
    app.register_blueprint(paystack_bp)
    app.register_blueprint(subscription_bp)  # NEW

    @app.get("/")
    def root():
        return jsonify(ok=True, service="naija-tax-guide-api")

    return app
