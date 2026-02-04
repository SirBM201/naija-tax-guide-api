# app/__init__.py
from flask import Flask
from flask_cors import CORS

from app.core.config import CORS_ORIGINS, API_PREFIX

from app.routes.health import bp as health_bp
from app.routes.accounts import bp as accounts_bp
from app.routes.subscriptions import bp as subs_bp
from app.routes.ask import bp as ask_bp
from app.routes.webhooks import bp as webhooks_bp
from app.routes.plans import bp as plans_bp

from app.routes.paystack import paystack_bp
from app.routes.paystack_webhook import bp as paystack_webhook_bp


def create_app() -> Flask:
    app = Flask(__name__)

    # ----------------------------
    # CORS
    # ----------------------------
    if (CORS_ORIGINS or "").strip() == "*":
        CORS(app, resources={r"/**": {"origins": "*"}})
    else:
        origins = [o.strip() for o in (CORS_ORIGINS or "").split(",") if o.strip()]
        CORS(app, resources={r"/**": {"origins": origins}})

    # ----------------------------
    # API Blueprints (with prefix)
    # ----------------------------
    app.register_blueprint(health_bp, url_prefix=API_PREFIX)
    app.register_blueprint(accounts_bp, url_prefix=API_PREFIX)
    app.register_blueprint(subs_bp, url_prefix=API_PREFIX)
    app.register_blueprint(ask_bp, url_prefix=API_PREFIX)
    app.register_blueprint(webhooks_bp, url_prefix=API_PREFIX)
    app.register_blueprint(plans_bp, url_prefix=API_PREFIX)

    # ----------------------------
    # Paystack (NO prefix inside blueprint already)
    # ----------------------------
    app.register_blueprint(paystack_bp)
    app.register_blueprint(paystack_webhook_bp)

    return app
