# app/main.py
import logging
from flask import jsonify
from werkzeug.exceptions import HTTPException

from app import create_app

app = create_app()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


@app.errorhandler(Exception)
def handle_any(err):
    if isinstance(err, HTTPException):
        return jsonify({"ok": False, "error": err.name}), err.code
    logging.exception("Unhandled error: %s", err)
    return jsonify({"ok": False, "error": "Internal Server Error"}), 500


@app.get("/api/_routes")
def list_routes():
    out = []
    for r in sorted(app.url_map.iter_rules(), key=lambda x: str(x)):
        out.append({"rule": str(r), "methods": sorted(list(r.methods or []))})
    return {"ok": True, "routes": out}
