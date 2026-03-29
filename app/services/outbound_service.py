from __future__ import annotations

import logging
import os
import time
from typing import List

import requests
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# -----------------------------
# WhatsApp Cloud API
# -----------------------------
WA_ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip()
WA_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()
WA_API_BASE = f"https://graph.facebook.com/v20.0/{WA_PHONE_NUMBER_ID}/messages"

# -----------------------------
# Telegram Bot API
# -----------------------------
TG_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TG_API_BASE = f"https://api.telegram.org/bot{TG_BOT_TOKEN}"

MAX_CHUNK = 1200
OUTBOUND_VERSION = "outbound_service_v2_retry_safe"


def _chunk_text(text: str, max_len: int = MAX_CHUNK) -> List[str]:
    t = (text or "").strip()
    if not t:
        return []
    if len(t) <= max_len:
        return [t]

    chunks: List[str] = []
    start = 0
    while start < len(t):
        end = min(start + max_len, len(t))
        slice_ = t[start:end]
        cut = max(slice_.rfind("\n"), slice_.rfind(" "))
        if cut > 200:
            end = start + cut
            slice_ = t[start:end]
        chunks.append(slice_.strip())
        start = end
    return [c for c in chunks if c]


def _build_session() -> Session:
    session = requests.Session()
    retry = Retry(
        total=4,
        connect=4,
        read=4,
        backoff_factor=1.0,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["POST"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def _post_with_attempts(
    *,
    session: Session,
    url: str,
    json_payload: dict,
    headers: dict | None = None,
    timeout: int = 20,
    attempts: int = 4,
    label: str = "outbound",
) -> bool:
    for attempt in range(1, attempts + 1):
        try:
            r = session.post(url, json=json_payload, headers=headers, timeout=timeout)
            if r.status_code < 300:
                return True

            logging.warning(
                "[%s] %s send failed attempt=%s status=%s body=%s",
                OUTBOUND_VERSION,
                label,
                attempt,
                r.status_code,
                r.text[:600],
            )

            if attempt < attempts:
                time.sleep(min(attempt, 3))
        except Exception as e:
            logging.exception(
                "[%s] %s send exception attempt=%s: %s",
                OUTBOUND_VERSION,
                label,
                attempt,
                e,
            )
            if attempt < attempts:
                time.sleep(min(attempt, 3))

    return False


def send_whatsapp_text(to_phone: str, text: str, *, preview_url: bool = False) -> bool:
    if not (WA_ACCESS_TOKEN and WA_PHONE_NUMBER_ID):
        logging.warning(
            "[%s] WhatsApp env not set (WHATSAPP_ACCESS_TOKEN/WHATSAPP_PHONE_NUMBER_ID)",
            OUTBOUND_VERSION,
        )
        return False

    to_phone = (to_phone or "").strip()
    if not to_phone:
        return False

    headers = {
        "Authorization": f"Bearer {WA_ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }

    session = _build_session()
    ok_any = False

    try:
        for part in _chunk_text(text):
            payload = {
                "messaging_product": "whatsapp",
                "to": to_phone,
                "type": "text",
                "text": {"preview_url": bool(preview_url), "body": part},
            }

            sent = _post_with_attempts(
                session=session,
                url=WA_API_BASE,
                json_payload=payload,
                headers=headers,
                timeout=20,
                attempts=4,
                label="WA",
            )
            if sent:
                ok_any = True
    finally:
        session.close()

    return ok_any


def send_telegram_text(chat_id: str | int, text: str) -> bool:
    if not TG_BOT_TOKEN:
        logging.warning("[%s] Telegram env not set (TELEGRAM_BOT_TOKEN)", OUTBOUND_VERSION)
        return False

    cid = str(chat_id or "").strip()
    if not cid:
        return False

    session = _build_session()
    ok_any = False

    try:
        for part in _chunk_text(text):
            payload = {"chat_id": cid, "text": part}

            sent = _post_with_attempts(
                session=session,
                url=f"{TG_API_BASE}/sendMessage",
                json_payload=payload,
                headers=None,
                timeout=25,
                attempts=5,
                label="TG",
            )
            if sent:
                ok_any = True
    finally:
        session.close()

    return ok_any
