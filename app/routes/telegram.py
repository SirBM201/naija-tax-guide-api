import os
import re
import requests
from flask import Blueprint, request, jsonify

bp = Blueprint("telegram", __name__)

TG_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
BASE_URL = os.getenv("PUBLIC_API_BASE_URL", "").strip()

CODE_RE = re.compile(r"^[A-Z0-9]{6,12}$")

def tg_send(chat_id: int, text: str):
    url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
    requests.post(url, json={"chat_id": chat_id, "text": text}, timeout=15)

@bp.post("/telegram/webhook")
def telegram_webhook():
    data = request.get_json(silent=True) or {}

    msg = data.get("message") or data.get("edited_message") or {}
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    text = (msg.get("text") or "").strip()

    user = msg.get("from") or {}
    tg_user_id = user.get("id")

    # ACK quickly
    if not chat_id or not tg_user_id or not text:
        return jsonify({"ok": True})

    parts = text.strip().split()
    cmd = parts[0].lower()

    # Support "/link CODE"
    if cmd in ("/link", "link") and len(parts) >= 2:
        code = parts[1].strip().upper()
    else:
        return jsonify({"ok": True})

    if not CODE_RE.match(code):
        tg_send(chat_id, "❌ Invalid code format. Use: /link ABCD1234")
        return jsonify({"ok": True})

    try:
        resp = requests.post(
            f"{BASE_URL}/api/link-tokens/consume",
            json={"provider": "tg", "code": code, "provider_user_id": str(tg_user_id)},
            timeout=15,
        )
        j = resp.json()
    except Exception:
        tg_send(chat_id, "⚠️ Linking failed due to network error. Please try again.")
        return jsonify({"ok": True})

    if j.get("ok"):
        tg_send(chat_id, "✅ Linked successfully! Your Telegram is now connected to your account.")
    else:
        tg_send(chat_id, "❌ Invalid or expired code. Please request a new code from your dashboard/admin.")

    return jsonify({"ok": True})
