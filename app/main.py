# app/main.py
# ============================================================
# Naija Tax Guide – Production Main App
# Implements a 7‑Layer Professional Answer Framework
# ============================================================

import os
import re
import json
import logging
from datetime import datetime, timezone
from typing import Optional

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client

# ------------------------------------------------------------
# App & Logging
# ------------------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", force=True)

# ------------------------------------------------------------
# ENV
# ------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# ------------------------------------------------------------
# CORS
# ------------------------------------------------------------
CORS(app)

# ------------------------------------------------------------
# Supabase
# ------------------------------------------------------------
supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc():
    return datetime.now(timezone.utc).isoformat()

def normalize_question(q: str) -> str:
    q = (q or "").lower()
    q = re.sub(r"[^a-z0-9\s]", " ", q)
    return re.sub(r"\s+", " ", q).strip()

DISCLAIMER = (
    "_Disclaimer: This is general guidance. "
    "Confirm with FIRS / State IRS or a qualified tax professional._"
)

def format_answer(question: str, answer: str) -> str:
    return f"""
**Jurisdiction:** Nigeria (FIRS / State IRS)

### Direct Answer
{answer}

### Who Is Responsible?
- Final consumers bear VAT cost
- Businesses collect and remit

### Exemptions
- Basic food items
- Medical services
- Educational services

### Compliance Checklist
- Confirm registration
- Check exemptions
- File returns on time

### Clarification Needed
- Individual or business?
- State of operation?

{DISCLAIMER}
""".strip()

# ------------------------------------------------------------
# AI
# ------------------------------------------------------------
def ai_answer(question: str) -> str:
    if not OPENAI_API_KEY:
        return "AI temporarily unavailable."
    payload = {
        "model": OPENAI_MODEL,
        "messages": [
            {"role": "system", "content": "You are a Nigerian tax assistant."},
            {"role": "user", "content": question[:2000]},
        ],
        "temperature": 0.2,
    }
    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
    r = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload, timeout=30)
    data = r.json()
    return data["choices"][0]["message"]["content"].strip()

# ------------------------------------------------------------
# Resolver
# ------------------------------------------------------------
def resolve_answer(question: str) -> str:
    nq = normalize_question(question)
    res = supabase.table("qa_library").select("answer").eq("normalized_question", nq).limit(1).execute().data
    if res:
        return format_answer(question, res[0]["answer"])
    return format_answer(question, ai_answer(question))

# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True, "time": now_utc()})

@app.post("/ask")
def ask():
    body = request.get_json(silent=True) or {}
    q = (body.get("question") or "").strip()
    if not q:
        return jsonify({"ok": False, "error": "question required"}), 400
    return jsonify({"ok": True, "answer": resolve_answer(q)})

# ------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
