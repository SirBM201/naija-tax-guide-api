# app/__init__.py
import os
from flask import Flask
from flask_cors import CORS

# Core blueprints
from app.routes.health import bp as health_bp
from app.routes.accounts import bp as accounts_bp
from app.routes.subscriptions import bp as subs_bp
from app.routes.ask import bp as ask_bp
from app.routes.webhooks import bp as webhooks_bp
from app.routes.plans import bp as plans_bp
from app.routes.link_tokens import bp as link_tokens_bp
from app.routes.whatsapp import bp as whatsapp_bp
from app.routes.telegram import bp as telegram_bp  # if you created it
from app.routes.admin_link_tokens import bp as admin_link_tokens_bp
from app.routes.debug_routes import bp as debug_routes_bp
from app.routes.accounts_admin import bp as accounts_admin_bp
from app.routes.meta import bp as meta_bp

# Paystack
from app.routes.paystack import paystack_bp
from app.routes.paystack_webhook import bp as paystack_webhook_bp


def create_app() -> Flask:
    app = Flask(__name__)

    # ------------------------------------------------------------
    # CORS
    # CORS_ORIGINS="https://your-frontend.vercel.app,http://localhost:3000"
    # ------------------------------------------------------------
    origins_raw = os.getenv("CORS_ORIGINS", "*").strip()
    origins = "*" if origins_raw == "*" else [o.strip() for o in origins_raw.split(",") if o.strip()]

    CORS(
        app,
        resources={r"/api/*": {"origins": origins}},
        supports_credentials=True,
    )

    # ------------------------------------------------------------
    # Register ALL routes under /api
    # ------------------------------------------------------------
    api_prefix = "/api"

    # Core routes
    app.register_blueprint(health_bp, url_prefix=api_prefix)
    app.register_blueprint(accounts_bp, url_prefix=api_prefix)
    app.register_blueprint(subs_bp, url_prefix=api_prefix)
    app.register_blueprint(ask_bp, url_prefix=api_prefix)
    app.register_blueprint(webhooks_bp, url_prefix=api_prefix)
    app.register_blueprint(plans_bp, url_prefix=api_prefix)
    app.register_blueprint(link_tokens_bp, url_prefix="/api")
    app.register_blueprint(whatsapp_bp, url_prefix="/api")
    app.register_blueprint(telegram_bp, url_prefix="/api")
    app.register_blueprint(admin_link_tokens_bp, url_prefix="/api")
    app.register_blueprint(debug_routes_bp, url_prefix="/api")
    app.register_blueprint(accounts_admin_bp, url_prefix="/api")
    app.register_blueprint(meta_bp, url_prefix="/api")

    # Paystack routes
    app.register_blueprint(paystack_bp, url_prefix=api_prefix)
    app.register_blueprint(paystack_webhook_bp, url_prefix=api_prefix)

    return app
