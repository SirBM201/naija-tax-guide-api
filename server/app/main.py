import os
from flask import Flask, jsonify
from supabase import create_client

def create_app():
    app = Flask(__name__)

    supabase_url = os.getenv("SUPABASE_URL", "")
    supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
    if not supabase_url or not supabase_key:
        raise RuntimeError("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing")

    app.config["SUPABASE"] = create_client(supabase_url, supabase_key)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"}), 200

    from app.paystack.routes import paystack_bp
    from app.whatsapp.routes import whatsapp_bp

    app.register_blueprint(paystack_bp)
    app.register_blueprint(whatsapp_bp)

    return app

app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
