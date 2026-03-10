from __future__ import annotations

from flask import Blueprint, jsonify, request

bp = Blueprint("web", __name__)


def _client_ip() -> str | None:
    forwarded = (request.headers.get("X-Forwarded-For") or "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip() or None
    return (request.remote_addr or "").strip() or None


@bp.get("/web/ping")
def web_ping():
    """
    Lightweight route to confirm the web blueprint is mounted correctly.
    """
    return (
        jsonify(
            {
                "ok": True,
                "service": "naija-tax-guide-api",
                "route_group": "web",
                "message": "Web routes are mounted correctly.",
            }
        ),
        200,
    )


@bp.get("/web/status")
def web_status():
    """
    Small diagnostic-safe web status endpoint.
    Does not require authentication.
    Keeps app.routes.web valid and non-conflicting.
    """
    return (
        jsonify(
            {
                "ok": True,
                "route_group": "web",
                "request": {
                    "method": request.method,
                    "path": request.path,
                    "client_ip": _client_ip(),
                    "user_agent": (request.headers.get("User-Agent") or "").strip() or None,
                },
            }
        ),
        200,
    )
