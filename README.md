# Swood Social API

## Local
npm i
cp .env.example .env
# édite .env (JWT_SECRET, CORS_ORIGINS, PRESETS, MAX_UPLOAD_MB)
node server.js

## Docker
docker build -t swood-social-api .
docker run -p 3000:3000 --env-file .env -v $(pwd)/uploads:/app/uploads swood-social-api

## Render / Railway
- Crée un service web Node.
- Variables d'env: PORT, JWT_SECRET, CORS_ORIGINS, PRESETS, MAX_UPLOAD_MB.
- Monte un volume persistant sur /app/uploads (recommandé).
