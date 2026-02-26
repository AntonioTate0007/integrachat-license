# IntegraChat License Server — Railway / Render / Fly.io Deployment

## Quick Deploy to Railway (free, 5 min)

1. Go to https://railway.app → New Project → Deploy from GitHub
2. Connect your `integrachat` repo, select the `license_server/` folder as root
3. Add these **Environment Variables** in Railway dashboard:
   - `JWT_SECRET`   → run `python -c "import secrets; print(secrets.token_hex(64))"` and paste
   - `ADMIN_TOKEN`  → a strong password you'll use to create/manage keys
   - `PORT`         → Railway sets this automatically
4. Railway detects `requirements.txt` and starts the app via:
   `uvicorn app:app --host 0.0.0.0 --port $PORT`
5. Your license server URL will be: `https://your-app.up.railway.app`

## Add Procfile (Railway reads this)
Create `license_server/Procfile`:
```
web: uvicorn app:app --host 0.0.0.0 --port $PORT
```

## Create your first license key
```bash
curl -X POST https://your-app.up.railway.app/keys/create \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tier": "professional", "notes": "Windermere Dentistry", "expires_days": 365}'
```

## Developer key (pre-seeded, always works)
Key: DEV-INTEGRACHAT-2025-ANT
Tier: developer (3 seats, no expiry)
Use this for local testing only.

## Connect IntegraChat server to the license server
In backend/main.py, set:
  LICENSE_SERVER_URL = "https://your-app.up.railway.app"

The IntegraChat server sends POST /activate on startup and POST /refresh every 30 days.
If the license server is unreachable, a 7-day grace period allows continued operation.

## Tier Definitions
| Tier         | Seats | Price   |
|-------------|-------|---------|
| starter     | 5     | $49/mo  |
| professional| 15    | $99/mo  |
| enterprise  | 9999  | $199/mo |
| developer   | 3     | Free    |
