# wsgi.py (repo root)
from app.main import app  # <-- this matches your earlier working command: app.main:app

# Gunicorn will load "app" from this file: wsgi:app
