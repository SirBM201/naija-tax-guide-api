# app/core/utils.py
import logging
import re
from datetime import datetime, timezone, date
from typing import Any, Optional
from flask import jsonify, request
from werkzeug.exceptions import HTTPException

def init_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        force=True,
    )

def register_error_handlers(app):
    @app.errorhandler(Exception)
    def _handle_unexpected(err):
        if isinstance(err, HTTPException):
            return jsonify({"ok": False, "error": err.name}), err.code
        logging.exception("Unhandled error: %s", err)
        return jsonify({"ok": False, "error": "Something went wrong while processing your request. Please try again."}), 500

    @app.before_request
    def _log_incoming():
        try:
            logging.info("REQ %s %s", request.method, request.path)
        except Exception:
            pass

    @app.after_request
    def _log_outgoing(resp):
        try:
            logging.info("RES %s %s -> %s", request.method, request.path, resp.status_code)
        except Exception:
            pass
        return resp

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def today_utc() -> date:
    return now_utc().date()

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default

def parse_iso_dt(s: Any) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None

def normalize_phone(raw: str) -> str:
    s = (raw or "").strip()
    return s.replace(" ", "").replace("+", "")

def normalize_question(q: str) -> str:
    s = (q or "").strip().lower()
    s = re.sub(r"[^a-z0-9\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s
