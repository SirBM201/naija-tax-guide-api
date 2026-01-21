# app/main.py
# ============================================================
# Naija Tax Guide – Production Main App
# (Single-file, copy‑replace safe)
# ============================================================

import os
import re
import json
import hmac
import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone, date
from typing import Any, Optional, Dict, Tuple, List

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client

# ------------------------------------------------------------
# App
# ------------------------------------------------------------
app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    force=True,
)

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def today_utc() -> date:
    return now_utc().date()

def normalize_phone(raw: str) -> str:
    return (raw or "").replace("+", "").replace(" ", "").strip()

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

# ------------------------------------------------------------
# ENV
# ------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

# ------------------------------------------------------------
# Supabase
# ------------------------------------------------------------
supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# ------------------------------------------------------------
# Markdown formatter (NON‑AI)
# ------------------------------------------------------------
DISCLAIMER = (
    "_Disclaimer: This is general guidance. For binding advice, confirm with FIRS / your State IRS "
    "or a qualified tax professional._"
)

def format_markdown_answer(question: str, raw_answer: str) -> str:
    a = (raw_answer or "").strip()
    if not a:
        return (
            "### Direct Answer\n"
            "I need more details to answer correctly.\n\n"
            "- Are you an **individual** or a **business**?\n"
            "- Which **state** are you in?\n\n"
            f"{DISCLAIMER}"
        )

    if "###" in a:
        return f"{a}\n\n{DISCLAIMER}"

    return (
        f"### Direct Answer\n{a}\n\n"
        "### What to do next\n"
        "- Confirm your state tax authority\n"
        "- Keep records and receipts\n\n"
        "### Common mistakes\n"
        "- Filing with wrong authority\n"
        "- Poor documentation\n\n"
        f"{DISCLAIMER}"
    )

# ------------------------------------------------------------
# AI (fallback only)
# ------------------------------------------------------------
def ai_answer_text(question: str) -> str:
    if not OPENAI_API_KEY:
        return "Service temporarily unavailable."

    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": "You are a Nigerian tax assistant. Respond professionally in Markdown."},
            {"role": "user", "content": question},
        ],
        "temperature": 0.2,
    }

    r = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=30,
    )

    if r.status_code >= 300:
        return "Unable to generate answer at the moment."

    return r.json()["choices"][0]["message"]["content"]

# ------------------------------------------------------------
# Core Resolver
# ------------------------------------------------------------
def resolve_answer(phone: str, question: str) -> str:
    # (Library + cache would sit here)
    ai_raw = ai_answer_text(question)
    return format_markdown_answer(question, ai_raw)

# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True, "time": iso(now_utc())})

@app.post("/ask")
def ask():
    body = request.get_json(silent=True) or {}
    wa_phone = normalize_phone(body.get("wa_phone"))
    question = (body.get("question") or "").strip()

    if not wa_phone or not question:
        return jsonify({"ok": False, "error": "wa_phone and question required"}), 400

    answer = resolve_answer(wa_phone, question)

    return jsonify({
        "ok": True,
        "answer": answer,
        "audio_url": None,
        "plan_expiry": None,
    })
