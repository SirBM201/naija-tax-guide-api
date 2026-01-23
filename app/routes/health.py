# app/routes/health.py
from flask import Blueprint

bp = Blueprint("health", __name__)

@bp.get("/health")
def health():
    return {"ok": True}
