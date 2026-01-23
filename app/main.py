# app/main.py
from app import create_app

# Gunicorn will load: app.main:app
app = create_app()
