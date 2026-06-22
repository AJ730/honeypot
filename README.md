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
