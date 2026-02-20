# app/routes/debug_mail.py

import os
from flask import Blueprint, jsonify

bp = Blueprint("debug_mail", __name__)

@bp.get("/debug/mail")
def debug_mail():
    return jsonify({
        "MAIL_ENABLED": os.getenv("MAIL_ENABLED"),
        "MAIL_HOST": os.getenv("MAIL_HOST"),
        "MAIL_PORT": os.getenv("MAIL_PORT"),
        "MAIL_USER_SET": bool(os.getenv("MAIL_USER")),
        "MAIL_PASS_SET": bool(os.getenv("MAIL_PASS")),
        "MAIL_FROM_EMAIL": os.getenv("MAIL_FROM_EMAIL"),
    })
