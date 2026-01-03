import os
from flask import Flask, jsonify

from supabase import create_client

# -----------------------------
# App setup
# -----------------------------
def create_app():
    app = Flask(__name__)

    # ---- Env ----
    supabase_url = os.getenv("SUPABASE_URL", "")
    supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
    if not supabase_url or not supabase_key:
        raise RuntimeError("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing")

    app.config["SUPABASE"] = create_client(supabase_url, supabase_key)

    # ---- Health ----
    @app.get("/health")
    def health():
        return jsonify({"status": "ok"}), 200

    # ---- Register Paystack routes ----
    from app.paystack.routes import paystack_bp
    app.register_blueprint(paystack_bp)

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
