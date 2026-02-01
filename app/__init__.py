from flask import Flask, jsonify
from flask_cors import CORS

from app.core.config import allowed_origins
from app.core.utils import init_logging, register_error_handlers


def create_app() -> Flask:
    init_logging()

    app = Flask(__name__)
    CORS(app, resources={r"/*": {"origins": allowed_origins}})

    register_error_handlers(app)

    # Blueprints
    from app.routes.health import bp as health_bp
    from app.routes.ask_routes import bp as ask_bp
    from app.routes.paystack_routes import bp as paystack_bp
    from app.routes.subscription_routes import bp as subscription_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(ask_bp)
    app.register_blueprint(paystack_bp)
    app.register_blueprint(subscription_bp)

    @app.get("/")
    def root():
        return jsonify(ok=True, service="naija-tax-guide-api")

    return app
