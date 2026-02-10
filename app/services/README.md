# Naija Tax Guide Backend (Phase 1)

## Endpoints
- GET  /health
- POST /accounts
- GET  /subscription/status
- POST /subscription/activate  (admin-only, header X-Admin-Key)
- POST /ask  (guarded by subscription)

## ENV Vars (Koyeb)
- SUPABASE_URL
- SUPABASE_SERVICE_ROLE_KEY
- ADMIN_API_KEY
- API_PREFIX            ("" or "/api")
- CORS_ORIGINS          ("*" or "https://your-frontend.vercel.app,http://localhost:3000")

## Local run
pip install -r requirements.txt
export API_PREFIX=/api
export CORS_ORIGINS=http://localhost:3000
flask --app app.main run --port 8000
