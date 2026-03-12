# app/routes/dev_tools.py

from flask import Blueprint
from app.scripts.seed_tax_sources import seed_sources

bp = Blueprint("dev_tools", __name__)

@bp.route("/dev/seed-tax")
def seed_tax():
    seed_sources()
    return {"status": "seeded"}
