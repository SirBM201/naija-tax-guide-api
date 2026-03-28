from __future__ import annotations

import os
from html import escape
from typing import Any

from flask import Blueprint, jsonify, request, Response

from app.services.channel_payment_delivery_service import deliver_channel_payment_link
from app.services.paystack_service import verify_transaction

bp = Blueprint("channel_payment", __name__)


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _humanize_plan_code(plan_code: str) -> str:
    code = _clean(plan_code).lower()
    if not code:
        return "Not available"
    return code.replace("_", " ").title()


def _build_telegram_return_link() -> str:
    bot_username = _clean(request.args.get("bot")) or _clean(os.getenv("TELEGRAM_BOT_USERNAME"))
    if bot_username:
        if bot_username.startswith("@"):
            bot_username = bot_username[1:]
        return f"https://t.me/{bot_username}"
    return "https://t.me"


def _build_whatsapp_return_link(provider_user_id: str) -> str:
    phone = "".join(ch for ch in _clean(provider_user_id) if ch.isdigit())
    if phone:
        return f"https://wa.me/{phone}?text=Hi"
    return "https://wa.me/"


def _render_channel_return_page(
    *,
    title: str,
    message: str,
    button_label: str,
    button_url: str,
    reference: str,
    plan_code: str,
    status_text: str,
) -> Response:
    pretty_plan = _humanize_plan_code(plan_code)

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <title>{escape(title)}</title>
  <style>
    body {{
      margin: 0;
      padding: 0;
      font-family: Arial, sans-serif;
      background: #0f172a;
      color: #e5e7eb;
    }}
    .wrap {{
      max-width: 640px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }}
    .card {{
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 18px;
      padding: 24px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.25);
    }}
    .badge {{
      display: inline-block;
      padding: 8px 12px;
      border-radius: 999px;
      background: #052e16;
      color: #86efac;
      font-weight: 700;
      margin-bottom: 16px;
    }}
    .badge.pending {{
      background: #3b2f0b;
      color: #fde68a;
    }}
    .badge.error {{
      background: #3b0a0a;
      color: #fca5a5;
    }}
    h1 {{
      margin: 0 0 12px;
      font-size: 28px;
      line-height: 1.2;
    }}
    p {{
      margin: 0 0 14px;
      font-size: 17px;
      line-height: 1.6;
      color: #d1d5db;
    }}
    .meta {{
      margin-top: 20px;
      padding: 16px;
      border-radius: 14px;
      background: #0b1220;
      border: 1px solid #1f2937;
      font-size: 15px;
      line-height: 1.7;
    }}
    .btn {{
      display: inline-block;
      margin-top: 22px;
      padding: 14px 18px;
      border-radius: 12px;
      background: #4f46e5;
      color: white;
      text-decoration: none;
      font-weight: 700;
      font-size: 16px;
    }}
    .small {{
      margin-top: 16px;
      font-size: 14px;
      color: #9ca3af;
      line-height: 1.6;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="badge">Payment processed</div>
      <h1>{escape(title)}</h1>
      <p>{escape(message)}</p>

      <div class="meta">
        <div><strong>Status:</strong> {escape(status_text or "unknown")}</div>
        <div><strong>Plan:</strong> {escape(pretty_plan)}</div>
        <div><strong>Reference:</strong> {escape(reference or "Not available")}</div>
      </div>

      <a class="btn" href="{escape(button_url)}">{escape(button_label)}</a>

      <div class="small">
        You can now return to your channel and continue using Naija Tax Guide.<br>
        Your channel will also receive the confirmation message automatically after the payment webhook is processed.
      </div>
    </div>
  </div>
</body>
</html>"""
    return Response(html, status=200, mimetype="text/html")


def _render_pending_page(
    *,
    title: str,
    message: str,
    button_label: str,
    button_url: str,
    reference: str,
    plan_code: str,
    status_text: str,
) -> Response:
    pretty_plan = _humanize_plan_code(plan_code)

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <title>{escape(title)}</title>
  <style>
    body {{
      margin: 0;
      padding: 0;
      font-family: Arial, sans-serif;
      background: #0f172a;
      color: #e5e7eb;
    }}
    .wrap {{
      max-width: 640px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }}
    .card {{
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 18px;
      padding: 24px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.25);
    }}
    .badge {{
      display: inline-block;
      padding: 8px 12px;
      border-radius: 999px;
      background: #3b2f0b;
      color: #fde68a;
      font-weight: 700;
      margin-bottom: 16px;
    }}
    h1 {{
      margin: 0 0 12px;
      font-size: 28px;
      line-height: 1.2;
    }}
    p {{
      margin: 0 0 14px;
      font-size: 17px;
      line-height: 1.6;
      color: #d1d5db;
    }}
    .meta {{
      margin-top: 20px;
      padding: 16px;
      border-radius: 14px;
      background: #0b1220;
      border: 1px solid #1f2937;
      font-size: 15px;
      line-height: 1.7;
    }}
    .btn {{
      display: inline-block;
      margin-top: 22px;
      padding: 14px 18px;
      border-radius: 12px;
      background: #4f46e5;
      color: white;
      text-decoration: none;
      font-weight: 700;
      font-size: 16px;
    }}
    .small {{
      margin-top: 16px;
      font-size: 14px;
      color: #9ca3af;
      line-height: 1.6;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="badge">Verification pending</div>
      <h1>{escape(title)}</h1>
      <p>{escape(message)}</p>

      <div class="meta">
        <div><strong>Status:</strong> {escape(status_text or "pending")}</div>
        <div><strong>Plan:</strong> {escape(pretty_plan)}</div>
        <div><strong>Reference:</strong> {escape(reference or "Not available")}</div>
      </div>

      <a class="btn" href="{escape(button_url)}">{escape(button_label)}</a>

      <div class="small">
        If payment was completed successfully, your channel confirmation message should arrive shortly.
      </div>
    </div>
  </div>
</body>
</html>"""
    return Response(html, status=200, mimetype="text/html")


@bp.post("/channel/payment/send-link")
def channel_payment_send_link():
    try:
        body = request.get_json(silent=True) or {}

        account_id = _clean(body.get("account_id"))
        channel_type = _clean(body.get("channel_type")).lower()
        provider_user_id = _clean(body.get("provider_user_id"))
        plan_code = _clean(body.get("plan_code"))

        if not account_id:
            return jsonify(
                {
                    "ok": False,
                    "error": "account_id_required",
                    "fix": "Pass account_id in the JSON body.",
                }
            ), 400

        if channel_type not in {"whatsapp", "telegram"}:
            return jsonify(
                {
                    "ok": False,
                    "error": "invalid_channel_type",
                    "fix": "Use whatsapp or telegram for automatic payment link delivery.",
                    "allowed": ["whatsapp", "telegram"],
                }
            ), 400

        if not provider_user_id:
            return jsonify(
                {
                    "ok": False,
                    "error": "provider_user_id_required",
                    "fix": "Pass provider_user_id in the JSON body.",
                }
            ), 400

        if not plan_code:
            return jsonify(
                {
                    "ok": False,
                    "error": "plan_code_required",
                    "fix": "Pass a valid plan_code in the JSON body.",
                }
            ), 400

        result = deliver_channel_payment_link(
            account_id=account_id,
            channel_type=channel_type,
            provider_user_id=provider_user_id,
            plan_code=plan_code,
        )

        if not result.get("ok"):
            return jsonify(result), 400

        return jsonify(result), 200

    except Exception as e:
        return jsonify(
            {
                "ok": False,
                "error": "channel_payment_send_link_failed",
                "where": "app.routes.channel_payment.channel_payment_send_link",
                "root_cause": repr(e),
                "fix": "Check channel_payment_delivery_service and request payload.",
            }
        ), 500


@bp.get("/channel/payment/return")
def channel_payment_return():
    """
    Channel-aware Paystack return page.
    This is UX only. Webhook remains the source of truth for activation.
    Example:
    /api/channel/payment/return?reference=...&channel_type=telegram&provider_user_id=...&plan_code=...
    """
    reference = _clean(request.args.get("reference"))
    channel_type = _clean(request.args.get("channel_type")).lower()
    provider_user_id = _clean(request.args.get("provider_user_id"))
    plan_code = _clean(request.args.get("plan_code"))

    if channel_type == "telegram":
        button_label = "Return to Telegram"
        button_url = _build_telegram_return_link()
    elif channel_type == "whatsapp":
        button_label = "Return to WhatsApp"
        button_url = _build_whatsapp_return_link(provider_user_id)
    else:
        button_label = "Open channel"
        button_url = _build_telegram_return_link()

    if not reference:
        return _render_pending_page(
            title="Payment reference missing",
            message="We could not find the payment reference in the return URL.",
            button_label=button_label,
            button_url=button_url,
            reference="",
            plan_code=plan_code,
            status_text="missing_reference",
        )

    try:
        verified = verify_transaction(reference)
        tx = (verified or {}).get("data") or {}
        status_text = _clean(tx.get("status")).lower()
        md = tx.get("metadata") or {}

        if not plan_code:
            plan_code = _clean(md.get("plan_code"))
        if not channel_type:
            channel_type = _clean(md.get("channel_type")).lower()
        if not provider_user_id:
            provider_user_id = _clean(md.get("provider_user_id"))

        if channel_type == "telegram":
            button_label = "Return to Telegram"
            button_url = _build_telegram_return_link()
        elif channel_type == "whatsapp":
            button_label = "Return to WhatsApp"
            button_url = _build_whatsapp_return_link(provider_user_id)
        else:
            button_label = "Open channel"
            button_url = _build_telegram_return_link()

    except Exception as e:
        return _render_pending_page(
            title="Payment verification pending",
            message=(
                "Your payment is being checked. If payment was completed successfully, "
                "your channel confirmation message should arrive shortly."
            ),
            button_label=button_label,
            button_url=button_url,
            reference=reference,
            plan_code=plan_code,
            status_text=f"verify_error: {type(e).__name__}",
        )

    if status_text == "success":
        return _render_channel_return_page(
            title="Payment successful",
            message=(
                "Your payment was received successfully. Your subscription activation "
                "and channel confirmation are being finalized."
            ),
            button_label=button_label,
            button_url=button_url,
            reference=reference,
            plan_code=plan_code,
            status_text=status_text,
        )

    return _render_pending_page(
        title="Payment not completed",
        message=(
            "The payment did not return with a successful status yet. "
            "You can return to your channel and try again if needed."
        ),
        button_label=button_label,
        button_url=button_url,
        reference=reference,
        plan_code=plan_code,
        status_text=status_text or "unknown",
    )
