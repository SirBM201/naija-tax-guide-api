from __future__ import annotations

import os

from flask import Blueprint, jsonify, request

from app.services.admin_semantic_service import (
    semantic_dashboard_summary,
    list_embeddings,
    get_embedding_detail,
    update_embedding_review_status,
    update_embedding_trust_manually,
    block_embedding_and_cache,
    low_trust_embeddings,
    top_reused_embeddings,
)

bp = Blueprint("admin_semantic", __name__)


def _admin_key() -> str:
    return (os.getenv("ADMIN_KEY") or "").strip()


def _require_admin():
    expected = _admin_key()
    got = (request.headers.get("X-Admin-Key") or "").strip()

    if not expected:
        return jsonify({
            "ok": False,
            "error": "admin_key_not_configured",
            "root_cause": "ADMIN_KEY env var is missing",
        }), 500

    if got != expected:
        return jsonify({
            "ok": False,
            "error": "unauthorized",
            "root_cause": "invalid_admin_key",
        }), 401

    return None


@bp.get("/admin/semantic/summary")
def admin_semantic_summary():
    fail = _require_admin()
    if fail:
        return fail

    res = semantic_dashboard_summary()
    return jsonify(res), (200 if res.get("ok") else 400)


@bp.get("/admin/semantic/embeddings")
def admin_semantic_list_embeddings():
    fail = _require_admin()
    if fail:
        return fail

    review_status = (request.args.get("review_status") or "").strip() or None
    limit = int((request.args.get("limit") or "50").strip() or "50")

    res = list_embeddings(review_status=review_status, limit=limit)
    return jsonify(res), (200 if res.get("ok") else 400)


@bp.get("/admin/semantic/embeddings/low-trust")
def admin_semantic_low_trust():
    fail = _require_admin()
    if fail:
        return fail

    limit = int((request.args.get("limit") or "50").strip() or "50")
    res = low_trust_embeddings(limit=limit)
    return jsonify(res), (200 if res.get("ok") else 400)


@bp.get("/admin/semantic/embeddings/top-reused")
def admin_semantic_top_reused():
    fail = _require_admin()
    if fail:
        return fail

    limit = int((request.args.get("limit") or "50").strip() or "50")
    res = top_reused_embeddings(limit=limit)
    return jsonify(res), (200 if res.get("ok") else 400)


@bp.get("/admin/semantic/embeddings/<embedding_id>")
def admin_semantic_detail(embedding_id: str):
    fail = _require_admin()
    if fail:
        return fail

    res = get_embedding_detail(embedding_id)
    return jsonify(res), (200 if res.get("ok") else 400)


@bp.patch("/admin/semantic/embeddings/<embedding_id>/review-status")
def admin_semantic_update_review_status(embedding_id: str):
    fail = _require_admin()
    if fail:
        return fail

    body = request.get_json(silent=True) or {}
    review_status = (body.get("review_status") or "").strip().lower()

    res = update_embedding_review_status(
        embedding_id=embedding_id,
        review_status=review_status,
    )
    return jsonify(res), (200 if res.get("ok") else 400)


@bp.patch("/admin/semantic/embeddings/<embedding_id>/trust-score")
def admin_semantic_update_trust_score(embedding_id: str):
    fail = _require_admin()
    if fail:
        return fail

    body = request.get_json(silent=True) or {}
    trust_score = float(body.get("trust_score", 0.85))

    res = update_embedding_trust_manually(
        embedding_id=embedding_id,
        trust_score=trust_score,
    )
    return jsonify(res), (200 if res.get("ok") else 400)


@bp.post("/admin/semantic/embeddings/<embedding_id>/block")
def admin_semantic_block_embedding(embedding_id: str):
    fail = _require_admin()
    if fail:
        return fail

    res = block_embedding_and_cache(embedding_id)
    return jsonify(res), (200 if res.get("ok") else 400)
