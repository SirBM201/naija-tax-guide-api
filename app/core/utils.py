import logging
from flask import jsonify
from werkzeug.exceptions import HTTPException

def init_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def json_error(message: str, http_status: int = 400, **extra):
    payload = {"ok": False, "message": message}
    payload.update(extra)
    return jsonify(payload), http_status

def register_error_handlers(app):
    @app.errorhandler(HTTPException)
    def handle_http_exc(e: HTTPException):
        return json_error(e.description or "Request failed", http_status=e.code or 400)

    @app.errorhandler(Exception)
    def handle_any(e: Exception):
        logging.exception("Unhandled error")
        return json_error("Server error", http_status=500)
