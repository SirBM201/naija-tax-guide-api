# app/main.py
import logging
from flask import Flask
from flask_cors import CORS

from .config import allowed_origins

def create_app() -> Flask:
    app = Flask(__name__)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        force=True,
    )

    CORS(
        app,
        resources={r"/*": {"origins": allowed_origins}},
        supports_credentials=False,
        allow_headers=["Content-Type", "x-admin-key"],
        methods=["GET", "POST", "OPTIONS"],
    )

    @app.get("/health")
    def health():
        return {"ok": True}

    return app

app = create_app()
