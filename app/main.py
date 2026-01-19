# app/main.py
import os
import re
import json
import hmac
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple, List

from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client

# ------------------------------------------------------------
# App
# ------------------------------------------------------------
app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ------------------------------------------------------------
# ENV
# ------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

# optional: used if you later enforce free daily limits in DB
FREE_DAILY_LIMIT = int(os.getenv("FREE_DAILY_LIMIT", "5"))

# ------------------------------------------------------------
# Supabase client
# ------------------------------------------------------------
if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    logging.warning("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing!")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.isoformat()

def normalize_question(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^\w\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def pick_answer(row: Dict[str, Any], lang: str) -> str:
    # English default; support db aliases too
    lang = (lang or "en").lower().strip()
    if lang not in ("en", "pcm", "yo", "ig", "ha"):
        lang = "en"

    # priority: lang-specific -> english -> legacy answer
    if lang == "en":
        return row.get("answer_en") or row.get("answer") or ""
    if lang == "pcm":
        return row.get("answer_pcm") or row.get("answer_pidgin") or row.get("answer_en") or row.get("answer") or ""
    if lang == "yo":
        return row.get("answer_yo") or row.get("answer_yoruba") or row.get("answer_en") or row.get("answer") or ""
    if lang == "ig":
        return row.get("answer_ig") or row.get("answer_igbo") or row.get("answer_en") or row.get("answer") or ""
    if lang == "ha":
        return row.get("answer_ha") or row.get("answer_hausa") or row.get("answer_en") or row.get("answer") or ""

    return row.get("answer_en") or row.get("answer") or ""

def safe_err(msg: str, status: int = 200):
    # user-safe error message (no internal wording)
    return jsonify({"ok": False, "answer": msg}), status

# ------------------------------------------------------------
# QA search (exact -> contains -> typo-tolerant RPC)
# ------------------------------------------------------------
def find_qa_answer(norm_q: str, lang: str) -> Optional[str]:
    if not norm_q:
        return None

    # 1) exact match on normalized_question
    try:
        r = (
            supabase.table("qa_library")
            .select("answer,answer_en,answer_pcm,answer_pidgin,answer_yo,answer_yoruba,answer_ig,answer_igbo,answer_ha,answer_hausa,normalized_question,enabled,priority")
            .eq("enabled", True)
            .eq("normalized_question", norm_q)
            .limit(1)
            .execute()
        )
        if r.data:
            return pick_answer(r.data[0], lang)
    except Exception as e:
        logging.exception("Exact match query failed: %s", e)

    # 2) contains match (simple fallback)
    try:
        r = (
            supabase.table("qa_library")
            .select("answer,answer_en,answer_pcm,answer_pidgin,answer_yo,answer_yoruba,answer_ig,answer_igbo,answer_ha,answer_hausa,normalized_question,enabled,priority")
            .eq("enabled", True)
            .like("normalized_question", f"%{norm_q}%")
            .order("priority", desc=True)
            .limit(1)
            .execute()
        )
        if r.data:
            return pick_answer(r.data[0], lang)
    except Exception as e:
        logging.exception("Contains match query failed: %s", e)

    # 3) typo tolerant RPC (MOST IMPORTANT)
    # Try the "expected" param names first, then fallback to alternative names if you created the function differently.
    try:
        rpc = supabase.rpc("qa_library_search", {"norm_query": norm_q, "min_sim": 0.25, "limit_n": 5}).execute()
        if rpc.data:
            # rpc.data rows include multilingual fields
            best = rpc.data[0]
            return (
                best.get("answer_en") if (lang == "en")
                else best.get("answer_pcm") if (lang == "pcm")
                else best.get("answer_yo") if (lang == "yo")
                else best.get("answer_ig") if (lang == "ig")
                else best.get("answer_ha") if (lang == "ha")
                else best.get("answer_en")
            ) or best.get("answer") or ""
    except Exception as e:
        logging.warning("RPC (norm_query/min_sim/limit_n) failed: %s", e)

    # fallback attempt for older signature: (q, min_similarity, max_results)
    try:
        rpc = supabase.rpc("qa_library_search", {"q": norm_q, "min_similarity": 0.25, "max_results": 5}).execute()
        if rpc.data:
            best = rpc.data[0]
            # if older rpc returns language columns, use them; else use answer
            return (
                best.get("answer_en") if (lang == "en")
                else best.get("answer_pcm") if (lang == "pcm")
                else best.get("answer_yo") if (lang == "yo")
                else best.get("answer_ig") if (lang == "ig")
                else best.get("answer_ha") if (lang == "ha")
                else best.get("answer_en")
            ) or best.get("answer") or ""
    except Exception as e:
        logging.warning("RPC (q/min_similarity/max_results) failed: %s", e)

    return None

# ------------------------------------------------------------
# Web chat endpoint
# ------------------------------------------------------------
@app.post("/webchat/ask")
def webchat_ask():
    try:
        payload = request.get_json(force=True) or {}
        wa_phone = (payload.get("wa_phone") or "").strip()
        text = (payload.get("text") or "").strip()
        lang = (payload.get("lang") or "en").strip().lower()  # English default

        if not wa_phone or not text:
            return safe_err("Please enter your WhatsApp number and your question.", 200)

        # NOTE: You said: for users not subscribed, do NOT mention AI/library/cache.
        # For now, we still allow library answers. Later we enforce free daily limits here.
        norm_q = normalize_question(text)

        ans = find_qa_answer(norm_q, lang)

        if ans:
            return jsonify({"ok": True, "answer": ans})

        # If no match in library, return a safe, neutral message (no AI wording)
        return jsonify({
            "ok": True,
            "answer": "I couldn’t find a matching answer for that question. Please try rephrasing it or check the Pricing page to unlock full access."
        })

    except Exception as e:
        logging.exception("webchat_ask fatal error: %s", e)
        # user-safe message
        return safe_err("Unable to answer right now. Please try again.", 200)

# ------------------------------------------------------------
# Health check
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True, "ts": iso(now_utc())})
