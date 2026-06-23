# Ollama Honeypot

Deceptive Ollama-compatible service. See `docs/superpowers/specs/2026-06-22-ollama-honeypot-design.md`.

## Run (local dev)
```bash
pip install -r requirements.txt
uvicorn honeypot.main:app --host 0.0.0.0 --port 11434
```

## Run (VM, Docker)
```bash
docker compose up -d --build
```
Honeypot listens on `:11434` (public). Real Ollama stays private on `:11500`.
Logs in the `honeypot_data` volume (`store.db`, `events.jsonl`).

## Operator access
Reach the VM over netbird VPN, `ssh 10.20.0.64`. The admin dashboard
(separate plan) binds to `:8080` on the VPN interface only.

## Dashboard

The admin dashboard is operator-only and never public. It listens only on
`127.0.0.1:8080` inside the VM; reach it through an SSH tunnel.

**Start with a password set:**
```bash
export DASHBOARD_PASSWORD=your-strong-password
# Optionally override the session-signing secret (recommended for production):
export DASHBOARD_SECRET=your-random-secret
docker compose up -d --build
```

**Open an SSH tunnel from your local machine:**
```bash
ssh -L 8080:127.0.0.1:8080 honeypot
```

Then browse to `http://localhost:8080` in your local browser.

- `DASHBOARD_PASSWORD` is required; compose will refuse to start without it.
- `DASHBOARD_SECRET` defaults to `please-change-me`; set it to a random string
  for production to prevent session-cookie forgery.
- The dashboard reads the same `honeypot_data` volume as the honeypot, so all
  logged events and the SQLite database are available in real time.
