# Ollama Honeypot — Design Spec

**Date:** 2026-06-22
**Status:** Approved — ready for implementation planning
**Phase:** Preliminary run (~1.5 months, single IP, TU Delft VM)

## 1. Objective

Deploy a deceptive, Ollama-compatible API service to study how scanners and
adversaries probe and interact with exposed LLM endpoints. The system serves a
mix of real and mocked responses, logs all interaction data for later analysis,
and enforces baseline ethical guardrails. An admin dashboard (operator-only)
provides live configuration, model management, traffic monitoring, and analytics.

## 2. Infrastructure

- **Host:** VM on TU Delft server, reached by operators over the netbird VPN
  (`netbird up --management-url https://vpn.delftintellab.com`, Keycloak / TU
  Delft SSO), `ssh` to `10.20.0.64`.
- **Specs:** 50 vCPU / 100 GB RAM / 500 GB storage.
- **Public network:** Port `11434` (Ollama default) opened for inbound TCP.
  Opened manually by Yuqian on a later date; disabled by default on these VMs.
- **Operator network:** Dashboard port `8080`, reachable only over the netbird
  VPN interface — never the public interface.
- **Duration:** ~1.5 month initial run on a single IP, extending through
  end of July–September while the team is away.

## 3. Architecture

Two strictly separated FastAPI applications run as separate processes/containers
on the VM. They share `config.yaml`, the SQLite store, and the JSONL log on disk,
and both can reach the real Ollama backend.

```
                          ┌─────────────────────────────────────────────┐
   Internet ──> :11434 ───│ FastAPI honeypot app (PUBLIC)                │
   (scanners)             │  proxy · router · fakes · guardrails · log  │──┬─> 127.0.0.1:11500 real Ollama
                          └─────────────────────────────────────────────┘  │      (qwen2.5:7b, qwen2.5:3b)
                                          │ shared config.yaml + SQLite     │
   Operator (netbird) ─> :8080 ──┐        │ + JSONL                         │
                          ┌───────┴───────────────────────────────────────┐│
                          │ FastAPI dashboard app (VPN-ONLY, login)        ││
                          │  config editor · model mgmt · live feed · stats│┘
                          └────────────────────────────────────────────────┘
```

### 3.1 Separation rationale

- The **public `:11434` port runs nothing but the honeypot.** A bug or exploit
  in the dashboard can never crash or expose the honeypot, and vice versa.
- Real Ollama binds to `127.0.0.1:11500` and is **never** exposed publicly. All
  external traffic is mediated by the honeypot middleware.
- The dashboard binds only to the netbird VPN interface and additionally
  requires a login password.

### 3.2 Components

**Honeypot app (public `:11434`):**

| Module | Responsibility |
|---|---|
| `main.py` | FastAPI app, wires endpoints |
| `proxy.py` | Forwards to real Ollama, preserving NDJSON streaming passthrough |
| `router.py` | Decides real-vs-fake per request (the 30% logic) |
| `fakes.py` | Generates all mocked endpoint responses |
| `guardrails.py` | Screens prompts; returns in-character refusal on a trip |
| `logging_store.py` | Writes SQLite rows + appends JSONL lines |
| `config.py` | Loads `config.yaml`, supports live reload |

**Dashboard app (VPN-only `:8080`):**

| Module | Responsibility |
|---|---|
| `dashboard/main.py` | FastAPI app, login/auth, serves pages |
| `dashboard/config_api.py` | Reads/writes `config.yaml` (live config editor) |
| `dashboard/models_api.py` | Pull/list/delete models via real Ollama API |
| `dashboard/feed.py` | Server-Sent Events live traffic stream |
| `dashboard/stats.py` | Analytics queries over SQLite |
| `dashboard/templates/`, `dashboard/static/` | HTMX + Chart.js frontend |

**Shared state:** `config.yaml`, `store.db` (SQLite), `events.jsonl`.

### 3.3 Tech stack

- **Language/framework:** Python + FastAPI (async, native NDJSON streaming
  support, fits existing PyCharm project).
- **Forwarding:** httpx (async) for proxying to real Ollama.
- **Dashboard frontend:** server-rendered HTML + HTMX + Server-Sent Events for
  the live feed + Chart.js for analytics. No separate build step.
- **Deployment:** Docker Compose.

## 4. Endpoint behavior & routing

### 4.1 Endpoint table

| Endpoint | Behavior |
|---|---|
| `/api/tags` | **Real** (proxied) — advertises both `qwen2.5:7b` and `qwen2.5:3b` |
| `/api/ps` | **Real** |
| `/api/show` | **Real** |
| `/api/generate`, `/api/chat` | Guardrail check first → ~30% fake (cached) / ~70% real |
| `/api/embed` | Fake — semi-dynamic, hardcoded template |
| `/api/create` | Fake — static |
| `/api/copy` | Fake — static |
| `/api/pull` | Fake — static |
| `/api/push` | Fake — static |
| `/api/delete` | Fake — static |
| `/api/version` | Fake — deterministic per source IP from a curated version list |

### 4.2 Routing for `/api/generate` and `/api/chat`

- **Fake-vs-real decision:** deterministic — `hash(source_ip + prompt) % 100 < fake_pct`
  (default `fake_pct = 30`). Because it is deterministic, the same probe from the
  same scanner always receives the same treatment (stable over repeat contact).
- **Real path (~70%):** forwarded to real Ollama, honoring the `model` field in
  the request. Both `qwen2.5:7b` and `qwen2.5:3b` are advertised in `/api/tags`,
  so **which model an adversary requests is the signal used to observe model
  preference** (the stretch goal). Streaming responses are passed through
  verbatim as NDJSON.
- **Fake path (~30%):** served from a small cache of canned, Ollama-formatted
  completions to reduce compute load.
- The fake rate and routing parameters live in `config.yaml` and are tunable live
  via the dashboard. Characteristic-based rules (short prompts, scanner
  fingerprints) may be layered on later once real traffic is observed.

### 4.3 Mocked endpoint specifications

**`/api/embed`** — template response with randomized values:
```json
{
  "model": "<echoed from request>",
  "embeddings": [[ /* random floats */ ]],
  "total_duration": "<random>",
  "load_duration": "<random>",
  "prompt_eval_count": "<random>"
}
```
Rule: randomize embedding values, `total_duration`, `prompt_eval_count`, and
`load_duration` on each call; scale dimensions/counts with input size.

**`/api/create`** → static `{ "status": "success" }`
**`/api/copy`** → static `200 OK`
**`/api/pull`** → static `{ "status": "success" }`
**`/api/push`** → static `{ "status": "success" }`
**`/api/delete`** → static `200 OK` — `"Model successfully deleted"`

**`/api/version`** — template `{ "version": "<value>" }`. Value drawn from a
curated list spanning old → current real Ollama releases, **deterministic per
source IP** (derived from a hash of the source IP) so a given scanner always sees
the same version on repeat contact. Goal: observe whether adversaries target
known-vulnerable older versions.

## 5. Logging

### 5.1 Mechanism

Dual write per request:
- **SQLite** (`store.db`) — structured, queryable rows for analysis (pandas,
  dashboard stats).
- **JSONL** (`events.jsonl`) — append-only, crash-durable raw record, rotated to
  bound disk usage over a multi-month run.

### 5.2 `requests` table fields

| Field | Notes |
|---|---|
| `id` | primary key |
| `ts` | timestamp |
| `source_ip` | client IP |
| `dest_ip` | destination IP (relevant if multiple dest IPs per VM) |
| `method` | HTTP method |
| `endpoint` | endpoint / action requested |
| `model` | model field from request, if any |
| `request_body` | request parameters (JSON, capped at ~64 KB) |
| `routed` | `real` \| `fake` \| `blocked` |
| `guardrail_trip` | boolean + reason |
| `response_status` | HTTP status served |
| `latency_ms` | server-side latency |
| `version_served` | value returned by `/api/version`, if applicable |

Purpose: all logged data feeds post-experiment analysis of scanner/adversary
behavior.

## 6. Ethical guardrails

`guardrails.py` screens `/api/generate` and `/api/chat` prompts **before** any
real-model call, using a keyword/pattern list plus a lightweight heuristic.
Patterns live in `config.yaml` and are tunable live via the dashboard.

On a trip:
- The real model is **never** called (no compute spent aiding misuse).
- An **in-character, Ollama-formatted refusal** is returned (looks like a normal
  model response, not an error — preserves the honeypot illusion).
- The request is logged with `routed = blocked` and the trip reason.

Target categories (at minimum): phishing, malware / exploit authoring, processing
stolen or leaked data, and similar criminal assistance.

## 7. Dashboard (operator-only)

`:8080`, netbird-VPN-only, password login. HTMX + SSE + Chart.js. Four panels:

1. **Live config editor** — form over `config.yaml`: fake %, routing thresholds,
   version list, guardrail patterns, per-endpoint real/fake behavior. Applies
   live (honeypot reloads config on change).
2. **Model management** — list installed models, pull/deploy new models from the
   Ollama library, delete models, choose the default real-response model. Drives
   the real Ollama backend via its `/api/pull`, `/api/delete`, `/api/tags`.
3. **Live traffic monitor** — real-time SSE feed of incoming requests (source IP,
   endpoint, prompt, real/fake/blocked decision, guardrail trips) plus a
   recent-history table.
4. **Analytics & stats** — Chart.js over SQLite: request volume over time, top
   source IPs, endpoint breakdown, model preference (3b vs 7b), guardrail-trip
   counts, version-probe distribution.

### 7.1 Live config reload

The dashboard writes `config.yaml`; the honeypot detects the change (file-watch
or version-stamp checked per request) and reloads, so changes such as the fake %
take effect without a redeploy.

## 8. Deployment

`docker-compose.yml` with three services:

| Service | Port | Exposure |
|---|---|---|
| `ollama` | `11500` | localhost only (private) |
| `honeypot` | `11434` | public |
| `dashboard` | `8080` | netbird VPN interface only |

Both `qwen2.5:7b` (Q4_K_M, default real responses) and `qwen2.5:3b` (Q4_K_M, fast
tier) are pulled on first boot. Docker Compose chosen for reproducibility and
easy teardown.

### 8.1 Model selection

| Tier | Model | Quantization |
|---|---|---|
| Default | Qwen2.5-7B-Instruct | Q4_K_M |
| Fast | Qwen2.5-3B | Q4_K_M |

Both run from day one to pursue the multi-model adversary-preference stretch goal.

## 9. Testing

pytest against the middleware, asserting:
- Each endpoint matches real Ollama's wire format (real-vs-fake responses must be
  indistinguishable on the wire, including streaming NDJSON shape).
- Fake-routing distribution ≈ 30% over a representative sample, and determinism
  (same `ip+prompt` → same decision).
- Guardrail trips return in-character refusals and are logged as `blocked`.
- `/api/version` is deterministic per source IP and varies across IPs.
- Config hot-reload changes behavior without restart.
- Dashboard config writes are picked up by the honeypot.

## 10. Out of scope (future / full-scale phase)

- Larger backend models and stress testing.
- Coding model and image-generation model tiers.
- Attaching ThunderLab IP addresses.
- ML-based fake-routing classifier.
- Multi-node / Postgres logging.
