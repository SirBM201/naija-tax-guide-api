# app/services/telegram.py
import logging
import re
import requests
from typing import Any, Dict, Optional, List

from app.core.config import TELEGRAM_BOT_TOKEN

TELEGRAM_API_BASE = "https://api.telegram.org/bot{token}"
TELEGRAM_TEXT_LIMIT = 4096


def _tg_url(method: str) -> str:
    return TELEGRAM_API_BASE.format(token=TELEGRAM_BOT_TOKEN) + f"/{method}"


def _clean_phone(value: str) -> str:
    """
    Normalizes phone-like strings to digits with optional leading + removed.
    e.g. "+234 801-234-5677" -> "2348012345677"
    """
    if not value:
        return ""
    s = str(value).strip()
    s = re.sub(r"[^\d]", "", s)
    return s


def _split_text(text: str, limit: int = TELEGRAM_TEXT_LIMIT) -> List[str]:
    """
    Splits long messages into chunks <= limit.
    Tries to split on paragraph boundaries first.
    """
    if not text:
        return [""]

    t = str(text)
    if len(t) <= limit:
        return [t]

    chunks: List[str] = []
    buf = ""

    # Prefer splitting on double newlines
    parts = t.split("\n\n")
    for part in parts:
        piece = (part + "\n\n")
        if len(piece) > limit:
            # fallback split hard
            if buf:
                chunks.append(buf.rstrip())
                buf = ""
            for i in range(0, len(piece), limit):
                chunks.append(piece[i : i + limit].rstrip())
            continue

        if len(buf) + len(piece) <= limit:
            buf += piece
        else:
            chunks.append(buf.rstrip())
            buf = piece

    if buf.strip():
        chunks.append(buf.rstrip())

    # Ensure no empty tail chunks
    return [c for c in chunks if c is not None and c != ""]


# ----------------------------
# Sending messages
# ----------------------------
def telegram_send_message(chat_id: int | str, text: str) -> bool:
    """
    Backwards-compatible: plain text send, auto-splitting.
    """
    return telegram_send_message_ex(chat_id=chat_id, text=text, parse_mode=None)


def telegram_send_message_markdown(chat_id: int | str, text: str) -> bool:
    """
    Sends with MarkdownV2.
    NOTE: MarkdownV2 requires escaping. Use escape_markdown_v2().
    """
    return telegram_send_message_ex(chat_id=chat_id, text=text, parse_mode="MarkdownV2")


def telegram_send_message_ex(
    chat_id: int | str,
    text: str,
    parse_mode: Optional[str] = None,
    reply_markup: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Robust sender:
    - supports parse_mode (None, "MarkdownV2")
    - supports reply_markup
    - auto-splits messages > 4096 chars
    """
    if not TELEGRAM_BOT_TOKEN:
        logging.error("TELEGRAM_BOT_TOKEN not set; cannot send Telegram messages")
        return False

    url = _tg_url("sendMessage")
    chunks = _split_text(text or "")

    ok_all = True
    for chunk in chunks:
        payload: Dict[str, Any] = {
            "chat_id": chat_id,
            "text": chunk,
            "disable_web_page_preview": True,
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode
        if reply_markup:
            payload["reply_markup"] = reply_markup

        try:
            r = requests.post(url, json=payload, timeout=20)
            if r.status_code != 200:
                logging.error("Telegram sendMessage failed: %s %s", r.status_code, r.text[:300])
                ok_all = False
                continue

            data = r.json()
            if not data.get("ok"):
                logging.error("Telegram sendMessage not ok: %s", str(data)[:300])
                ok_all = False

        except Exception as e:
            logging.exception("Telegram sendMessage exception: %s", e)
            ok_all = False

    return ok_all


# ----------------------------
# Phone capture helpers
# ----------------------------
def telegram_request_phone_keyboard(prompt_text: str = "Please share your phone number to continue.") -> Dict[str, Any]:
    """
    Returns a reply_markup that asks for a contact share.
    Use with telegram_send_message_ex(..., reply_markup=telegram_request_phone_keyboard()).
    """
    return {
        "keyboard": [
            [{"text": "Share my phone number", "request_contact": True}],
        ],
        "resize_keyboard": True,
        "one_time_keyboard": True,
    }


def extract_telegram_chat_id(update: Dict[str, Any]) -> Optional[int]:
    """
    Extract chat_id from typical Telegram update payload.
    """
    try:
        if "message" in update and update["message"].get("chat", {}).get("id") is not None:
            return int(update["message"]["chat"]["id"])
        if "edited_message" in update and update["edited_message"].get("chat", {}).get("id") is not None:
            return int(update["edited_message"]["chat"]["id"])
    except Exception:
        return None
    return None


def extract_telegram_text(update: Dict[str, Any]) -> str:
    """
    Extract message text.
    """
    try:
        msg = update.get("message") or update.get("edited_message") or {}
        return (msg.get("text") or "").strip()
    except Exception:
        return ""


def extract_telegram_phone(update: Dict[str, Any]) -> Optional[str]:
    """
    BEST-EFFORT extraction of a user phone number from Telegram update.

    IMPORTANT:
    - Telegram does NOT provide phone number by default.
    - Phone is only present if the user shares contact (request_contact),
      or if user manually types a phone number.

    Returns normalized digits e.g. "2348012345677" or None.
    """
    try:
        msg = update.get("message") or update.get("edited_message") or {}

        # 1) Contact share (best)
        contact = msg.get("contact")
        if contact and contact.get("phone_number"):
            phone = _clean_phone(contact.get("phone_number"))
            return phone if phone else None

        # 2) User typed a phone number into text (fallback)
        text = (msg.get("text") or "").strip()
        if text:
            # Extract long digit sequences that look like phones
            digits = _clean_phone(text)
            if 9 <= len(digits) <= 15:
                return digits

    except Exception:
        return None

    return None


# ----------------------------
# Markdown escaping (optional)
# ----------------------------
def escape_markdown_v2(text: str) -> str:
    """
    Escapes text for Telegram MarkdownV2.
    """
    if text is None:
        return ""
    s = str(text)
    # Telegram MarkdownV2 special chars
    specials = r"_*[]()~`>#+-=|{}.!\\"
    out = []
    for ch in s:
        if ch in specials:
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)
