from flask import Flask
from flask_cors import CORS

from .core.config import CORS_ORIGINS, API_PREFIX
from .routes.health import bp as health_bp
from .routes.accounts import bp as accounts_bp
from .routes.subscriptions import bp as subs_bp
from .routes.ask import bp as ask_bp

def create_app() -> Flask:
    app = Flask(__name__)

    # CORS
    if CORS_ORIGINS.strip() == "*":
        CORS(app, resources={r"/*": {"origins": "*"}})
    else:
        origins = [o.strip() for o in CORS_ORIGINS.split(",") if o.strip()]
        CORS(app, resources={r"/*": {"origins": origins}})

    # Register blueprints at optional prefix
    app.register_blueprint(health_bp, url_prefix=API_PREFIX)
    app.register_blueprint(accounts_bp, url_prefix=API_PREFIX)
    app.register_blueprint(subs_bp, url_prefix=API_PREFIX)
    app.register_blueprint(ask_bp, url_prefix=API_PREFIX)

    return app

