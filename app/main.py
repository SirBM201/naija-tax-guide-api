# app/main.py
from flask import Flask
from flask_cors import CORS

from .config import allowed_origins
from .routes.ask import bp as ask_bp
from .routes.health import bp as health_bp
from .routes.paystack_routes import bp as paystack_bp
from .routes.telegram_routes import bp as telegram_bp
from .routes.admin import bp as admin_bp

def create_app() -> Flask:
    app = Flask(__name__)

    # CORS
    CORS(
        app,
        resources={r"/*": {"origins": allowed_origins}},
        supports_credentials=False,
        allow_headers=["Content-Type", "x-admin-key"],
        methods=["GET", "POST", "OPTIONS"],
    )

    # Register routes
    app.register_blueprint(health_bp)
    app.register_blueprint(ask_bp)
    app.register_blueprint(paystack_bp)
    app.register_blueprint(telegram_bp)
    app.register_blueprint(admin_bp)

    return app

app = create_app()
