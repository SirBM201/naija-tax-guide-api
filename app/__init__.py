# app/__init__.py

from flask import Flask
from flask_cors import CORS

# Core blueprints
from app.routes.health import bp as health_bp
from app.routes.accounts import bp as accounts_bp
from app.routes.subscriptions import bp as subs_bp
from app.routes.ask import bp as ask_bp
from app.routes.webhooks import bp as webhooks_bp
from app.routes.plans import bp as plans_bp

# Paystack
from app.routes.paystack import paystack_bp
from app.routes.paystack_webhook import bp as paystack_webhook_bp


def create_app():
    app = Flask(__name__)

    # Enable CORS
    CORS(app)

    # Register core routes
    app.register_blueprint(health_bp)
    app.register_blueprint(accounts_bp)
    app.register_blueprint(subs_bp)
    app.register_blueprint(ask_bp)
    app.register_blueprint(webhooks_bp)
    app.register_blueprint(plans_bp)

    # Register Paystack routes
    app.register_blueprint(paystack_bp)
    app.register_blueprint(paystack_webhook_bp)

    return app
