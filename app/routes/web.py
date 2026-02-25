# app/routes/web.py
from __future__ import annotations

from flask import Blueprint, redirect, request

bp = Blueprint("web_compat", __name__)

# IMPORTANT:
# - This is a compatibility endpoint for the frontend calling /api/web/ask
# - It forwards the request to the existing /api/ask endpoint (your real handler)
# - strict_slashes=False ensures /web/ask and /web/ask/ behave the same

@bp.route("/web/ask", methods=["POST", "OPTIONS"], strict_slashes=False)
def web_ask_compat():
    # Preflight must be OK (204) so browsers stop blocking.
    if request.method == "OPTIONS":
        return ("", 204)

    # Forward POST to the canonical endpoint that already exists.
    # 308 keeps method and body (POST stays POST).
    return redirect("/api/ask", code=308)
