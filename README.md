# Ollama Honeypot

A deceptive, Ollama-compatible API service that studies how scanners and
adversaries probe exposed LLM endpoints. It serves a mix of real and faked
responses, logs every interaction, and enforces ethical guardrails. A separate,
operator-only **ops console** (web dashboard) provides live config editing,
model management, a live traffic feed, analytics, and system metrics.

Design spec: `docs/superpowers/specs/2026-06-22-ollama-honeypot-design.md`

---

## Architecture at a glance

```
                          ┌──────────────────────────────────────────┐
 Internet ─▶ :11434 ──────│ Honeypot (FastAPI, host network)         │──┬─▶ 127.0.0.1:11500  real Ollama (private)
 (scanners)               │  proxy · route · fake · guardrails · log │  │     qwen2.5:7b, qwen2.5:3b, …
                          └──────────────────────────────────────────┘  │
 Operator ─(SSH tunnel)─▶ :8080 ──┐  shares: config.yaml + store.db + events.jsonl
                          ┌────────┴─────────────────────────────────┐
                          │ Dashboard (FastAPI, 127.0.0.1 only)      │
                          │  config · models · live feed · analytics │
                          └──────────────────────────────────────────┘
```

| Service | Port | Exposure |
|---|---|---|
| Honeypot | `11434` | **Public** (the only thing the world reaches) |
| Real Ollama | `11500` | `127.0.0.1` only — never public |
| Dashboard | `8080` | `127.0.0.1` only — reach via SSH tunnel |

---

## 1. Connect to the VM

The honeypot runs on a TU Delft VM reached over the **NetBird VPN**.

1. **Install NetBird** (once): <https://app.netbird.io/install>
2. **Bring up the VPN** (re-run whenever it drops — the SSO session expires):
   ```bash
   netbird up --management-url https://vpn.delftintellab.com
   ```
   Choose **Keycloak** and sign in with TU Delft SSO. Check it with `netbird status`
   (you want `Management: Connected`). `netbird down` disconnects.
3. **SSH in.** Add this once to `~/.ssh/config` so you can just type `ssh honeypot`:
   ```
   Host honeypot 10.20.0.64
       HostName 10.20.0.64
       User ysong9
       IdentityFile ~/.ssh/<your-key>
       IdentitiesOnly yes
   ```
   Then:
   ```bash
   ssh honeypot
   ```
   Your public key must be installed in `ysong9`'s `~/.ssh/authorized_keys` on the VM.

---

## 2. Configure credentials (the `.env` file)

The dashboard requires a password. **You do not need to `export` anything** —
put the secrets in a `.env` file in the project directory and Docker Compose
loads it automatically.

On the VM, in the project directory (e.g. `~/honeypot`):

```bash
cat > .env <<'EOF'
DASHBOARD_PASSWORD=choose-a-strong-password
DASHBOARD_SECRET=paste-a-long-random-string
EOF
chmod 600 .env
```

Generate strong values with:
```bash
openssl rand -base64 24    # for DASHBOARD_PASSWORD
openssl rand -base64 48    # for DASHBOARD_SECRET
```

- **`DASHBOARD_PASSWORD`** (required) — the dashboard login. Compose refuses to
  start without it.
- **`DASHBOARD_SECRET`** (recommended) — signs the session cookie. If left empty
  the app generates a random one at startup, but then sessions don't survive a
  restart. Set it once in `.env` to keep logins stable.

> `.env` is git-ignored and `chmod 600` — keep it on the VM, not in the repo.
> (Using `export DASHBOARD_PASSWORD=…` in your shell also works, but it's
> per-shell and you'd have to redo it on every deploy. The `.env` file is the
> persistent way.)

---

## 3. Run it

From the project directory on the VM:

```bash
docker compose up -d --build
```

This starts four services: `ollama` (private backend), `ollama-init` (pulls
`qwen2.5:7b` + `qwen2.5:3b` on first boot), `honeypot` (public `:11434`), and
`dashboard` (`127.0.0.1:8080`).

Useful commands:
```bash
docker compose ps                 # status
docker compose logs -f honeypot   # follow honeypot logs
docker compose up -d --build      # apply code/config changes
docker compose down               # stop everything (volumes/data persist)
```

---

## 4. Open the dashboard (SSH tunnel)

The dashboard is loopback-only on the VM, so forward it to your laptop:

```bash
ssh -L 8080:127.0.0.1:8080 honeypot
```

Leave that running, then open **<http://localhost:8080>** in your browser and
log in with `DASHBOARD_PASSWORD`.

Tabs:
- **Overview** — KPIs, the live routing-mix bar (real/faked/blocked), system gauges.
- **Live traffic** — real-time stream of incoming requests (source IP, endpoint,
  model, routing decision, prompt, and any guardrail block reason). Shows requests
  that arrive *after* you open it.
- **Analytics** — charts over the full history (volume over time, routing mix,
  top endpoints, top source IPs).
- **Models** — list installed models with sizes; deploy a new one (dropdown +
  typeahead); delete models. Pulls run on the backend.
- **Config** — edit `config.yaml` live (validated; the honeypot hot-reloads).
  Includes a **Danger zone → Clear all logged data** button.

---

## 5. Guardrails

Two layers screen `/api/generate` and `/api/chat` prompts; a trip returns an
in-character refusal (HTTP 200, never an error) and is logged as `routed=blocked`.

1. **Keyword pre-filter** — instant, always on. Edit the patterns in the Config tab.
2. **LLM safety classifier** (optional) — an Ollama model (default
   `llama-guard3:1b`) classifies prompts as safe/unsafe. **Fails open**: if the
   classifier is missing or slow, the honeypot keeps serving.

To enable the LLM guard:
1. **Models** tab → deploy `llama-guard3:1b` (or `:8b`).
2. **Config** tab → set `llm_guard_enabled: true` → Save.

---

## 6. Where the data is logged

Every request is written to **two sinks**, both in the `honeypot_data` Docker
volume (mounted at `/app/data` in the honeypot container):

- **`store.db`** — SQLite, queryable (the dashboard reads this).
- **`events.jsonl`** — append-only JSON lines, rotated at 100 MB × 5 backups.

On the VM host:
```
/var/lib/docker/volumes/honeypot_honeypot_data/_data/{store.db,events.jsonl}
```

Each record: `ts, source_ip, dest_ip, method, endpoint, model, request_body`
(the prompt, capped 64 KB), `routed` (real/fake/blocked), `guardrail_trip`,
`response_status`, `latency_ms`, `version_served`.

Pull the data to your laptop for analysis:
```bash
scp honeypot:/var/lib/docker/volumes/honeypot_honeypot_data/_data/store.db .
```

Wipe it anytime via **Config → Danger zone → Clear all logged data**.

---

## 7. Open the honeypot to the world

The honeypot already listens on `0.0.0.0:11434` (including the VM's public IP),
and the VM host has no firewall blocking it. The remaining gate is the **upstream
network / Proxmox firewall** in front of the public IP — that's the
admin-managed step (ask the VM/network admin to allow inbound **TCP 11434**).

Only `11434` should ever be public. The dashboard (`8080`) and real Ollama
(`11500`) are bound to `127.0.0.1`, so they stay private even after the port opens.

Verify from an outside host once it's open:
```bash
curl http://<public-ip>:11434/api/version
```

---

## Local development (no Docker)

```bash
pip install -r requirements.txt
# Honeypot (needs a real Ollama at the configured real_ollama_url):
uvicorn honeypot.main:app --host 0.0.0.0 --port 11434
# Dashboard:
DASHBOARD_PASSWORD=dev uvicorn honeypot.dashboard.main:app --port 8080
```

Run the test suite:
```bash
pytest -q
```
