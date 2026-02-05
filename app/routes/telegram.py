from flask import Blueprint, request, jsonify
import os
import re
import requests

bp = Blueprint("telegram", __name__)

TG_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()

PUBLIC_API_BASE_URL = os.getenv(
    "PUBLIC_API_BASE_URL",
    "https://incredible-nonie-bmsconcept-37359733.koyeb.app"
).strip()

CODE_RE = re.compile(r"^[A-Z0-9]{6,12}$")

def _tg_send(chat_id: int, text: str) -> None:
    if not TG_TOKEN:
        return
    url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
    try:
        requests.post(url, json={"chat_id": chat_id, "text": text}, timeout=15)
    except Exception:
        pass

@bp.post("/telegram/webhook")
def telegram_webhook():
    data = request.get_json(silent=True) or {}

    msg = data.get("message") or data.get("edited_message") or {}
    if not msg:
        return jsonify({"ok": True})

    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    text = (msg.get("text") or "").strip()

    user = msg.get("from") or {}
    tg_user_id = user.get("id")

    if not chat_id or not tg_user_id or not text:
        return jsonify({"ok": True})

    parts = text.split()
    cmd = parts[0].lower()

    # /link CODE
    if cmd in ("/link", "link") and len(parts) >= 2:
        code = parts[1].strip().upper()
    else:
        # optional help:
        # _tg_send(chat_id, "Use: /link ABCD1234 to connect your account.")
        return jsonify({"ok": True})

    if not CODE_RE.match(code):
        _tg_send(chat_id, "❌ Invalid code format. Use: /link ABCD1234")
        return jsonify({"ok": True})

    # Consume code
    try:
        resp = requests.post(
            f"{PUBLIC_API_BASE_URL}/api/link-tokens/consume",
            json={
                "provider": "tg",
                "code": code,
                "provider_user_id": str(tg_user_id)
            },
            timeout=15
        )
        j = resp.json()
    except Exception:
        _tg_send(chat_id, "⚠️ Network error. Please try again.")
        return jsonify({"ok": True})

    if j.get("ok"):
        _tg_send(chat_id, "✅ Linked successfully! Your Telegram is now connected.")
    else:
        _tg_send(chat_id, "❌ Invalid or expired code. Please request a new code and try again.")

    return jsonify({"ok": True})
