# app/__init__.py
from flask import Flask
from flask_cors import CORS

from .core.config import CORS_ORIGINS, API_PREFIX
from .routes.health import bp as health_bp
from .routes.accounts import bp as accounts_bp
from .routes.subscriptions import bp as subs_bp
from .routes.ask import bp as ask_bp
from .routes.webhooks import bp as webhooks_bp
from .routes.plans import bp as plans_bp
from .routes.inbound import bp as inbound_bp
from app.routes.paystack import paystack_bp


def create_app() -> Flask:
    app = Flask(__name__)

    # CORS
    if (CORS_ORIGINS or "").strip() == "*":
        CORS(app, resources={r"/*": {"origins": "*"}})
    else:
        origins = [o.strip() for o in (CORS_ORIGINS or "").split(",") if o.strip()]
        CORS(app, resources={r"/*": {"origins": origins}})

    # Register blueprints at optional prefix
    app.register_blueprint(health_bp, url_prefix=API_PREFIX)
    app.register_blueprint(accounts_bp, url_prefix=API_PREFIX)
    app.register_blueprint(subs_bp, url_prefix=API_PREFIX)
    app.register_blueprint(ask_bp, url_prefix=API_PREFIX)
    app.register_blueprint(webhooks_bp, url_prefix=API_PREFIX)
    app.register_blueprint(plans_bp, url_prefix=API_PREFIX)
    app.register_blueprint(paystack_bp)

    # Inbound webhook endpoints (no prefix is fine, but keep consistent with your current)
    # If you want them under /api too, change to url_prefix=API_PREFIX
    app.register_blueprint(inbound_bp)

    return app
