# Honeypot Admin Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an operator-only admin dashboard for the Ollama honeypot — live config editing, model management, a live traffic feed, and analytics — reachable only via SSH tunnel.

**Architecture:** A SECOND, separate FastAPI app (`honeypot/dashboard/`) running as its own process/container, isolated from the public honeypot. It binds `127.0.0.1:8080` inside its container and is published to the VM's loopback only (operator reaches it via `ssh -L`). It shares three things with the honeypot on disk/network: `config.yaml` (it writes; the honeypot hot-reloads), the SQLite store `store.db` + `events.jsonl` (read-only, in the `honeypot_data` volume), and the real Ollama backend (reached at `http://ollama:11500` over the compose network for model management). Password login gates every page; a signed session cookie carries auth. Frontend is server-rendered HTML + HTMX + Server-Sent Events + Chart.js, no build step (vendored static assets).

**Tech Stack:** Python 3.11 (container) / 3.9 (local tests), FastAPI, Starlette, httpx (async, for Ollama), SQLite (stdlib), itsdangerous (signed cookies — already a Starlette dep), Jinja2 templates, HTMX + Chart.js (vendored static files), pytest.

## Global Constraints

- The dashboard is a SEPARATE app/process from the honeypot. It must NEVER be importable-coupled to `honeypot.main` in a way that could affect the public honeypot, and must never listen on the public honeypot port (11434).
- The dashboard binds `0.0.0.0:8080` INSIDE its container but is published ONLY to `127.0.0.1:8080` on the VM (SSH-tunnel access). No other exposure.
- Every dashboard route except the login page and static assets requires a valid session; unauthenticated requests redirect to `/login`.
- The admin password comes from the `DASHBOARD_PASSWORD` env var. If unset, the dashboard refuses to start (no default password).
- Config writes MUST be validated (construct `honeypot.config.Config(**parsed)`) before being written to `config.yaml`; an invalid edit is rejected with an error and the existing file is left untouched.
- The store (`store.db`, `events.jsonl`) is read-only from the dashboard. The dashboard never writes to the honeypot's logs.
- All DB paths / Ollama URL / config path come from env vars with sane defaults: `HONEYPOT_CONFIG` (default `config.yaml`), `HONEYPOT_DB` (default `store.db`), `DASHBOARD_OLLAMA_URL` (default `http://ollama:11500`), `DASHBOARD_PASSWORD` (required), `DASHBOARD_SECRET` (cookie signing key; default to a generated-at-start value with a warning).
- Local tests run with the `pytorch_basic` conda env (Python 3.9): `& "C:\Users\amala\anaconda3\envs\pytorch_basic\python.exe" -m pytest <path> -v`. Never bare python/pytest.
- Reuse `honeypot.config.Config`/`ConfigStore` and `honeypot.logging_store.LoggingStore` rather than reimplementing parsing/queries where practical.

---

### Task 1: Dashboard app skeleton + password auth

**Files:**
- Create: `honeypot/dashboard/__init__.py`
- Create: `honeypot/dashboard/auth.py`
- Create: `honeypot/dashboard/main.py`
- Create: `honeypot/dashboard/templates/base.html`
- Create: `honeypot/dashboard/templates/login.html`
- Create: `tests/test_dashboard_auth.py`

**Interfaces:**
- Produces: `honeypot.dashboard.main.create_dashboard(config_path, db_path, ollama_url, password, secret) -> FastAPI`. A module-level `app = create_dashboard(<env-driven>)` for uvicorn.
- Produces: `honeypot.dashboard.auth.make_session_cookie(secret) -> str`, `verify_session(cookie, secret) -> bool`, and a dependency/helper `require_login(request)` used to gate routes.
- Auth model: POST `/login` with form field `password`; on match set a signed cookie `dash_session` (via `itsdangerous.URLSafeTimedSerializer(secret)` signing the value `"ok"`), redirect to `/`. GET `/login` shows the form. Any protected route without a valid cookie → 303 redirect to `/login`. POST `/logout` clears the cookie.

- [ ] **Step 1: Write failing test `tests/test_dashboard_auth.py`**

```python
from starlette.testclient import TestClient
from honeypot.dashboard.main import create_dashboard


def build(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("fake_pct: 30\n")
    return create_dashboard(str(cfg), str(tmp_path / "store.db"),
                            "http://ollama:11500", password="secret", secret="k")


def test_root_requires_login(tmp_path):
    with TestClient(build(tmp_path)) as c:
        r = c.get("/", follow_redirects=False)
    assert r.status_code in (302, 303)
    assert "/login" in r.headers["location"]


def test_login_wrong_password(tmp_path):
    with TestClient(build(tmp_path)) as c:
        r = c.post("/login", data={"password": "nope"}, follow_redirects=False)
    assert r.status_code == 401 or "/login" in r.headers.get("location", "")


def test_login_then_access(tmp_path):
    with TestClient(build(tmp_path)) as c:
        r = c.post("/login", data={"password": "secret"}, follow_redirects=False)
        assert r.status_code in (302, 303)
        # cookie now set on the client; root should render
        r2 = c.get("/")
    assert r2.status_code == 200


def test_logout_clears_session(tmp_path):
    with TestClient(build(tmp_path)) as c:
        c.post("/login", data={"password": "secret"})
        c.post("/logout")
        r = c.get("/", follow_redirects=False)
    assert r.status_code in (302, 303)
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `& "C:\Users\amala\anaconda3\envs\pytorch_basic\python.exe" -m pytest tests/test_dashboard_auth.py -v`
Expected: FAIL (`ModuleNotFoundError: honeypot.dashboard.main`).

- [ ] **Step 3: Implement `honeypot/dashboard/auth.py`**

```python
from __future__ import annotations

from itsdangerous import BadSignature, URLSafeTimedSerializer

COOKIE_NAME = "dash_session"
_MAX_AGE = 60 * 60 * 12  # 12h


def make_session_cookie(secret: str) -> str:
    return URLSafeTimedSerializer(secret).dumps("ok")


def verify_session(cookie: str | None, secret: str) -> bool:
    if not cookie:
        return False
    try:
        URLSafeTimedSerializer(secret).loads(cookie, max_age=_MAX_AGE)
        return True
    except (BadSignature, Exception):
        return False
```

- [ ] **Step 4: Implement `honeypot/dashboard/main.py` (skeleton + auth routes)**

```python
from __future__ import annotations

import os

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from honeypot.dashboard import auth

_TEMPLATES = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))


def create_dashboard(config_path: str, db_path: str, ollama_url: str,
                     password: str, secret: str) -> FastAPI:
    if not password:
        raise RuntimeError("DASHBOARD_PASSWORD is required")
    app = FastAPI()
    app.state.config_path = config_path
    app.state.db_path = db_path
    app.state.ollama_url = ollama_url
    app.state.password = password
    app.state.secret = secret

    def logged_in(request: Request) -> bool:
        return auth.verify_session(request.cookies.get(auth.COOKIE_NAME), secret)

    app.state.logged_in = logged_in

    @app.get("/login", response_class=HTMLResponse)
    async def login_form(request: Request):
        return _TEMPLATES.TemplateResponse("login.html", {"request": request, "error": None})

    @app.post("/login")
    async def login(request: Request, password: str = Form(...)):
        if password != app.state.password:
            return _TEMPLATES.TemplateResponse(
                "login.html", {"request": request, "error": "Invalid password"}, status_code=401)
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(auth.COOKIE_NAME, auth.make_session_cookie(secret),
                        httponly=True, samesite="lax")
        return resp

    @app.post("/logout")
    async def logout():
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(auth.COOKIE_NAME)
        return resp

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        if not logged_in(request):
            return RedirectResponse("/login", status_code=303)
        return _TEMPLATES.TemplateResponse("base.html", {"request": request})

    return app


app = create_dashboard(
    os.environ.get("HONEYPOT_CONFIG", "config.yaml"),
    os.environ.get("HONEYPOT_DB", "store.db"),
    os.environ.get("DASHBOARD_OLLAMA_URL", "http://ollama:11500"),
    os.environ.get("DASHBOARD_PASSWORD", ""),
    os.environ.get("DASHBOARD_SECRET", "change-me-dev-secret"),
)
```

Note: the module-level `app` will raise if `DASHBOARD_PASSWORD` is unset. For import safety in tests we always call `create_dashboard(...)` directly with a password, so importing the module for tests must not trigger the env-driven `app`. To avoid that, guard the module-level app: only build it when `DASHBOARD_PASSWORD` is set, else set `app = None`. Implement that guard.

- [ ] **Step 5: Implement `templates/base.html` and `templates/login.html`**

`login.html`: a minimal HTML form POSTing to `/login` with a password field and `{{ error }}` display.
`base.html`: minimal authenticated landing page with a title "Honeypot Admin" and placeholder nav for the four panels (Config, Models, Live, Analytics) — panels filled in later tasks. Include `<script src="/static/htmx.min.js"></script>` (static added in Task 6; a 404 here is fine for now).

- [ ] **Step 6: Run tests to confirm pass**

Run: `& "C:\Users\amala\anaconda3\envs\pytorch_basic\python.exe" -m pytest tests/test_dashboard_auth.py -v`
Expected: 4 passed. (Install `itsdangerous`/`jinja2` into the env if missing — both ship with Starlette/FastAPI; verify first.)

- [ ] **Step 7: Commit**

```bash
git add honeypot/dashboard tests/test_dashboard_auth.py
git commit -m "feat(dashboard): app skeleton + password auth"
```

---

### Task 2: Config editor panel

**Files:**
- Create: `honeypot/dashboard/config_api.py`
- Modify: `honeypot/dashboard/main.py` (mount the config router; add panel to base.html)
- Create: `honeypot/dashboard/templates/_config_panel.html`
- Create: `tests/test_dashboard_config_api.py`

**Interfaces:**
- Consumes: `honeypot.config.Config` (for validation), `app.state.config_path`, `app.state.logged_in`.
- Produces: GET `/config` → returns the current `config.yaml` contents (raw YAML text) inside an editable form (HTMX partial). POST `/config` with form field `yaml_text` → parse + validate by constructing `Config(**yaml.safe_load(text))`; on success write atomically to `config_path` and return a success partial; on failure return a 400 partial with the validation error and DO NOT write the file.

- [ ] **Step 1: Write failing test `tests/test_dashboard_config_api.py`**

```python
import yaml
from starlette.testclient import TestClient
from honeypot.dashboard.main import create_dashboard

GOOD = ("fake_pct: 30\nreal_ollama_url: \"http://127.0.0.1:11500\"\n"
        "default_model: \"qwen2.5:7b\"\nadvertised_models: [\"qwen2.5:7b\"]\n"
        "versions: [\"0.12.6\"]\nguardrail_patterns: [\"phishing\"]\n"
        "fake_responses: [\"hi\"]\nmax_body_bytes: 65536\n")


def build(tmp_path):
    cfg = tmp_path / "config.yaml"; cfg.write_text(GOOD)
    app = create_dashboard(str(cfg), str(tmp_path / "store.db"),
                           "http://ollama:11500", password="s", secret="k")
    return app, cfg


def login(c):
    c.post("/login", data={"password": "s"})


def test_get_config_requires_login(tmp_path):
    app, _ = build(tmp_path)
    with TestClient(app) as c:
        r = c.get("/config", follow_redirects=False)
    assert r.status_code in (302, 303)


def test_get_config_returns_yaml(tmp_path):
    app, _ = build(tmp_path)
    with TestClient(app) as c:
        login(c)
        r = c.get("/config")
    assert r.status_code == 200
    assert "fake_pct" in r.text


def test_post_valid_config_writes_file(tmp_path):
    app, cfg = build(tmp_path)
    new = GOOD.replace("fake_pct: 30", "fake_pct: 55")
    with TestClient(app) as c:
        login(c)
        r = c.post("/config", data={"yaml_text": new})
    assert r.status_code == 200
    assert yaml.safe_load(cfg.read_text())["fake_pct"] == 55


def test_post_invalid_config_rejected_and_file_unchanged(tmp_path):
    app, cfg = build(tmp_path)
    before = cfg.read_text()
    with TestClient(app) as c:
        login(c)
        r = c.post("/config", data={"yaml_text": "fake_pct: 30\nmissing: everything\n"})
    assert r.status_code == 400
    assert cfg.read_text() == before  # untouched
```

- [ ] **Step 2: Run → fail.** `pytest tests/test_dashboard_config_api.py -v` → FAIL (no `/config`).

- [ ] **Step 3: Implement `honeypot/dashboard/config_api.py`**

```python
from __future__ import annotations

import os

import yaml
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from honeypot.config import Config


def register_config_routes(app):
    router = APIRouter()

    @router.get("/config", response_class=HTMLResponse)
    async def get_config(request: Request):
        if not app.state.logged_in(request):
            return RedirectResponse("/login", status_code=303)
        text = ""
        if os.path.exists(app.state.config_path):
            with open(app.state.config_path, "r", encoding="utf-8") as f:
                text = f.read()
        return HTMLResponse(_form(text, None, None))

    @router.post("/config", response_class=HTMLResponse)
    async def post_config(request: Request, yaml_text: str = Form(...)):
        if not app.state.logged_in(request):
            return RedirectResponse("/login", status_code=303)
        try:
            raw = yaml.safe_load(yaml_text)
            if not isinstance(raw, dict):
                raise ValueError("config root must be a mapping")
            Config(**raw)  # validate exactly like the honeypot will load it
        except Exception as exc:
            return HTMLResponse(_form(yaml_text, None, str(exc)), status_code=400)
        tmp = app.state.config_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(yaml_text)
        os.replace(tmp, app.state.config_path)  # atomic
        return HTMLResponse(_form(yaml_text, "Saved — honeypot will hot-reload.", None))

    app.include_router(router)


def _form(text: str, ok: str | None, err: str | None) -> str:
    msg = ""
    if ok:
        msg = f'<p style="color:green">{ok}</p>'
    if err:
        msg = f'<p style="color:red">Error: {err}</p>'
    return (
        f'{msg}<form hx-post="/config" hx-target="#config-panel">'
        f'<textarea name="yaml_text" rows="20" cols="80">{text}</textarea><br>'
        f'<button type="submit">Save config</button></form>'
    )
```

Mount it: in `main.py` `create_dashboard`, after routes, call `from honeypot.dashboard.config_api import register_config_routes; register_config_routes(app)`.

- [ ] **Step 4: Run → pass.** `pytest tests/test_dashboard_config_api.py -v` → 4 passed.

- [ ] **Step 5: Commit**

```bash
git add honeypot/dashboard tests/test_dashboard_config_api.py
git commit -m "feat(dashboard): live config editor panel with validation"
```

---

### Task 3: Analytics / stats API

**Files:**
- Create: `honeypot/dashboard/stats.py`
- Modify: `honeypot/dashboard/main.py` (mount stats router)
- Create: `tests/test_dashboard_stats.py`

**Interfaces:**
- Consumes: `app.state.db_path` (the honeypot's `store.db`), read-only.
- Produces: `honeypot.dashboard.stats.compute_stats(db_path: str) -> dict` returning JSON-serializable aggregates: `total_requests`, `by_endpoint` (list of {endpoint,count}), `by_routed` ({real,fake,blocked}), `top_source_ips` (list of {source_ip,count} top 10), `model_preference` (list of {model,count}), `guardrail_trips` (list of {reason,count}), `version_distribution` (list of {version_served,count}), `requests_over_time` (list of {bucket,count} by hour). And GET `/stats` (login-gated) returning that dict as JSON for Chart.js to fetch.

- [ ] **Step 1: Write failing test `tests/test_dashboard_stats.py`** — seed a `store.db` via `honeypot.logging_store.LoggingStore`, call `compute_stats`, assert the aggregates.

```python
from honeypot.logging_store import LoggingStore
from honeypot.dashboard.stats import compute_stats


def seed(tmp_path):
    db = str(tmp_path / "store.db")
    s = LoggingStore(db, str(tmp_path / "events.jsonl"))
    rows = [
        {"ts": "2026-06-22T10:00:00Z", "source_ip": "1.1.1.1", "endpoint": "/api/generate", "routed": "real", "model": "qwen2.5:7b"},
        {"ts": "2026-06-22T10:01:00Z", "source_ip": "1.1.1.1", "endpoint": "/api/generate", "routed": "fake", "model": "qwen2.5:3b"},
        {"ts": "2026-06-22T11:00:00Z", "source_ip": "2.2.2.2", "endpoint": "/api/version", "routed": "fake", "version_served": "0.11.4"},
        {"ts": "2026-06-22T11:05:00Z", "source_ip": "2.2.2.2", "endpoint": "/api/generate", "routed": "blocked", "guardrail_trip": "write malware", "model": "qwen2.5:7b"},
    ]
    for r in rows:
        s.log(r)
    return db


def test_compute_stats(tmp_path):
    db = seed(tmp_path)
    st = compute_stats(db)
    assert st["total_requests"] == 4
    assert st["by_routed"]["fake"] == 2
    assert st["by_routed"]["blocked"] == 1
    top = {d["source_ip"]: d["count"] for d in st["top_source_ips"]}
    assert top["1.1.1.1"] == 2
    trips = {d["reason"]: d["count"] for d in st["guardrail_trips"]}
    assert trips["write malware"] == 1
    models = {d["model"]: d["count"] for d in st["model_preference"]}
    assert models["qwen2.5:7b"] == 2
```

- [ ] **Step 2: Run → fail.**

- [ ] **Step 3: Implement `stats.py`** using read-only `sqlite3` GROUP BY queries for each aggregate. `compute_stats` opens the db read-only (`sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)`), runs the queries, returns the dict. Add the `/stats` JSON route (login-gated) in a `register_stats_routes(app)` that calls `compute_stats(app.state.db_path)`. Handle the empty-db / missing-table case by returning zeroed aggregates.

- [ ] **Step 4: Run → pass.**

- [ ] **Step 5: Commit** `feat(dashboard): analytics/stats API over SQLite`.

---

### Task 4: Live traffic feed (SSE)

**Files:**
- Create: `honeypot/dashboard/feed.py`
- Modify: `honeypot/dashboard/main.py` (mount feed router)
- Create: `tests/test_dashboard_feed.py`

**Interfaces:**
- Consumes: `app.state.db_path` read-only.
- Produces: `honeypot.dashboard.feed.fetch_since(db_path: str, last_id: int, limit: int = 100) -> list[dict]` returning request rows with `id > last_id` ascending (the new events). And GET `/feed` — an SSE endpoint (`text/event-stream`) that polls `fetch_since` ~every 1s and emits each new row as a `data: <json>\n\n` event, tracking the max id seen. Login-gated. Use a `StreamingResponse` with an async generator that `await asyncio.sleep(1)` between polls.

- [ ] **Step 1: Write failing test `tests/test_dashboard_feed.py`** — seed rows, assert `fetch_since` returns only rows after a given id, ascending. (The SSE endpoint's loop is hard to unit-test fully; test `fetch_since` thoroughly and assert `/feed` returns `content-type: text/event-stream` with a 1-iteration cap via a test hook or by reading the first event with a short client timeout. Keep the loop testable by factoring the body builder.)

```python
from honeypot.logging_store import LoggingStore
from honeypot.dashboard.feed import fetch_since


def test_fetch_since(tmp_path):
    db = str(tmp_path / "store.db")
    s = LoggingStore(db, str(tmp_path / "events.jsonl"))
    for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]:
        s.log({"source_ip": ip, "endpoint": "/api/version", "routed": "fake"})
    rows = fetch_since(db, last_id=1)
    assert [r["source_ip"] for r in rows] == ["2.2.2.2", "3.3.3.3"]
    assert all(r["id"] > 1 for r in rows)
```

- [ ] **Step 2: Run → fail.**

- [ ] **Step 3: Implement `feed.py`** — `fetch_since` (read-only sqlite, `SELECT * FROM requests WHERE id > ? ORDER BY id ASC LIMIT ?`). `register_feed_routes(app)` adds `/feed` SSE via `StreamingResponse(gen(), media_type="text/event-stream")` where `gen` loops: fetch_since(max_id), for each row `yield f"data: {json.dumps(row)}\n\n".encode()`, update max_id, `await asyncio.sleep(1)`. Initialize max_id to the current max id so the feed shows only NEW events after page load. Login-gate (if not logged in, return 303).

- [ ] **Step 4: Run → pass.**

- [ ] **Step 5: Commit** `feat(dashboard): live traffic feed via SSE`.

---

### Task 5: Model management API

**Files:**
- Create: `honeypot/dashboard/models_api.py`
- Modify: `honeypot/dashboard/main.py` (mount models router)
- Create: `tests/test_dashboard_models_api.py`

**Interfaces:**
- Consumes: `app.state.ollama_url`, an injectable httpx client (`app.state.http` — set on startup; injectable in tests via `create_dashboard(..., client=...)` — add this optional param).
- Produces:
  - GET `/models` → list installed models (proxies real Ollama `GET /api/tags`), returns an HTMX partial table.
  - POST `/models/pull` form `name` → kick off `POST {ollama}/api/pull` (non-streaming `{"model": name, "stream": false}`); return a partial reporting started/finished. (Pull can be slow; for v1 do a blocking call with a long timeout and report the final status. A streaming/progress UI is out of scope for v1 — note this in the partial.)
  - POST `/models/delete` form `name` → `DELETE {ollama}/api/delete` `{"model": name}`; return updated list partial.
- All login-gated. Add optional `client` param to `create_dashboard` and store as `app.state.http` (mirror the honeypot's injectable-client pattern).

- [ ] **Step 1: Write failing test `tests/test_dashboard_models_api.py`** — use `httpx.MockTransport` to fake the Ollama backend; assert `/models` lists models, `/models/pull` calls the upstream `/api/pull`, `/models/delete` calls `/api/delete`.

```python
import httpx
from starlette.testclient import TestClient
from honeypot.dashboard.main import create_dashboard


def handler(request):
    if request.url.path == "/api/tags":
        return httpx.Response(200, json={"models": [{"name": "qwen2.5:7b"}]})
    if request.url.path == "/api/pull":
        return httpx.Response(200, json={"status": "success"})
    if request.url.path == "/api/delete":
        return httpx.Response(200, text="")
    return httpx.Response(404)


def build(tmp_path):
    cfg = tmp_path / "config.yaml"; cfg.write_text("fake_pct: 30\n")
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return create_dashboard(str(cfg), str(tmp_path / "store.db"),
                            "http://ollama:11500", password="s", secret="k", client=client)


def login(c): c.post("/login", data={"password": "s"})


def test_models_list(tmp_path):
    with TestClient(build(tmp_path)) as c:
        login(c)
        r = c.get("/models")
    assert r.status_code == 200
    assert "qwen2.5:7b" in r.text


def test_models_pull(tmp_path):
    with TestClient(build(tmp_path)) as c:
        login(c)
        r = c.post("/models/pull", data={"name": "qwen2.5:3b"})
    assert r.status_code == 200


def test_models_delete(tmp_path):
    with TestClient(build(tmp_path)) as c:
        login(c)
        r = c.post("/models/delete", data={"name": "qwen2.5:7b"})
    assert r.status_code == 200
```

- [ ] **Step 2: Run → fail.**

- [ ] **Step 3: Implement `models_api.py`** with `register_models_routes(app)` using `app.state.http` for the three Ollama calls (use the `forward`-style pattern; for pull use a long timeout). Add the `client` param to `create_dashboard` (store on `app.state.http`; create a real `httpx.AsyncClient(timeout=600)` on startup if not injected; close on shutdown).

- [ ] **Step 4: Run → pass.**

- [ ] **Step 5: Commit** `feat(dashboard): model management (list/pull/delete)`.

---

### Task 6: Frontend assembly + vendored static assets

**Files:**
- Modify: `honeypot/dashboard/templates/base.html` (assemble the 4 panels: Config form, Models table, Live feed pane, Analytics charts)
- Create: `honeypot/dashboard/static/htmx.min.js` (vendored)
- Create: `honeypot/dashboard/static/chart.min.js` (vendored)
- Create: `honeypot/dashboard/static/app.js` (SSE wiring for the live feed; Chart.js fetch+render from `/stats`)
- Create: `honeypot/dashboard/static/style.css`
- Modify: `honeypot/dashboard/main.py` (mount `StaticFiles` at `/static`)
- Create: `tests/test_dashboard_pages.py`

**Interfaces:**
- Consumes: all prior routes (`/config`, `/models`, `/stats`, `/feed`).
- Produces: a single authenticated dashboard page wiring: Config panel (HTMX loads `/config`), Models panel (HTMX loads `/models`), Live panel (JS `EventSource("/feed")` appending rows to a table), Analytics panel (JS fetches `/stats` and renders Chart.js bar/line charts). Mount static files: `app.mount("/static", StaticFiles(directory=.../static), name="static")`.

- [ ] **Step 1: Write failing test `tests/test_dashboard_pages.py`** — login, GET `/`, assert the page references the four panels and `/static/` assets, and that `/static/app.js` serves 200.

```python
from starlette.testclient import TestClient
from honeypot.dashboard.main import create_dashboard


def build(tmp_path):
    cfg = tmp_path / "config.yaml"; cfg.write_text("fake_pct: 30\n")
    return create_dashboard(str(cfg), str(tmp_path / "store.db"),
                            "http://ollama:11500", password="s", secret="k")


def test_dashboard_page_has_panels(tmp_path):
    with TestClient(build(tmp_path)) as c:
        c.post("/login", data={"password": "s"})
        r = c.get("/")
    assert r.status_code == 200
    for needle in ["Config", "Models", "Live", "Analytics", "/static/app.js"]:
        assert needle in r.text


def test_static_served(tmp_path):
    with TestClient(build(tmp_path)) as c:
        c.post("/login", data={"password": "s"})
        r = c.get("/static/app.js")
    assert r.status_code == 200
```

- [ ] **Step 2: Run → fail.**

- [ ] **Step 3: Implement** the templates, static mount, vendored JS (download htmx.min.js and chart.min.js — or commit minimal known-good copies; if network is unavailable in the build env, create small placeholder JS that the tests accept, and note that real htmx/chart.js must be vendored before deploy), and `app.js` wiring `EventSource("/feed")` + a `fetch("/stats")` Chart.js render. Keep CSS minimal.

- [ ] **Step 4: Run → pass.**

- [ ] **Step 5: Commit** `feat(dashboard): frontend assembly + static assets`.

---

### Task 7: Deployment — compose service + docs

**Files:**
- Modify: `docker-compose.yml` (add `dashboard` service)
- Modify: `Dockerfile` (ensure `honeypot/dashboard` is copied — if the Dockerfile copies the whole `honeypot` package it already is; verify)
- Modify: `README.md` (document the dashboard + SSH-tunnel access)
- Create: `tests/test_dashboard_import.py` (import-with-env smoke)

**Interfaces:**
- Produces: a `dashboard` compose service sharing the honeypot's image, on the compose bridge network (to reach `ollama:11500`), publishing ONLY `127.0.0.1:8080:8080`, mounting `./config.yaml` and the `honeypot_data` volume (read access to `store.db`), with env `DASHBOARD_PASSWORD`, `DASHBOARD_SECRET`, `HONEYPOT_CONFIG=/app/config.yaml`, `HONEYPOT_DB=/app/data/store.db`, `DASHBOARD_OLLAMA_URL=http://ollama:11500`, command `uvicorn honeypot.dashboard.main:app --host 0.0.0.0 --port 8080`.

- [ ] **Step 1: Add the `dashboard` service to `docker-compose.yml`**

```yaml
  dashboard:
    build: .
    depends_on:
      - ollama
    ports:
      - "127.0.0.1:8080:8080"   # operator reaches via: ssh -L 8080:127.0.0.1:8080 honeypot
    volumes:
      - ./config.yaml:/app/config.yaml
      - honeypot_data:/app/data
    environment:
      - HONEYPOT_CONFIG=/app/config.yaml
      - HONEYPOT_DB=/app/data/store.db
      - DASHBOARD_OLLAMA_URL=http://ollama:11500
      - DASHBOARD_PASSWORD=${DASHBOARD_PASSWORD:?set DASHBOARD_PASSWORD}
      - DASHBOARD_SECRET=${DASHBOARD_SECRET:-please-change-me}
    command: ["uvicorn", "honeypot.dashboard.main:app", "--host", "0.0.0.0", "--port", "8080"]
    restart: unless-stopped
```

Note: the dashboard mounts the SAME `honeypot_data` volume as the honeypot (the honeypot runs `network_mode: host` but still mounts that named volume), so it can read `store.db`/`events.jsonl`. The config.yaml bind mount is shared with the honeypot so edits hot-reload.

- [ ] **Step 2: Verify the Dockerfile copies `honeypot/dashboard`.** If `Dockerfile` has `COPY honeypot ./honeypot`, the dashboard package is included — no change needed. If it copies submodules individually, add the dashboard. Also ensure `jinja2`/`itsdangerous`/`python-multipart` are installed (python-multipart is required by FastAPI for Form()); add `python-multipart` to `requirements.txt` if missing.

- [ ] **Step 3: Update `README.md`** with a "Dashboard" section: how to set `DASHBOARD_PASSWORD`, bring it up, and reach it: `ssh -L 8080:127.0.0.1:8080 honeypot` then browse `http://localhost:8080`.

- [ ] **Step 4: Write `tests/test_dashboard_import.py`** — set `DASHBOARD_PASSWORD` env + import `honeypot.dashboard.main`, assert `app` is not None; unset password → importing builds `app = None` (guarded).

- [ ] **Step 5: Run the FULL suite** `& "...pytorch_basic...python.exe" -m pytest -q` — all honeypot + dashboard tests pass.

- [ ] **Step 6: Commit** `feat(dashboard): compose service + docs`.

---

## Self-Review

**Spec coverage (spec §7):**
- §7 panel 1 Config editor → Task 2 ✓
- §7 panel 2 Model management → Task 5 ✓
- §7 panel 3 Live traffic monitor (SSE) → Task 4 + frontend Task 6 ✓
- §7 panel 4 Analytics (Chart.js) → Task 3 + frontend Task 6 ✓
- §7 auth (login) + VPN/tunnel-only → Task 1 + Task 7 (127.0.0.1 publish) ✓
- §7.1 live config reload → Task 2 writes config.yaml; honeypot already hot-reloads (with validation fallback) ✓
- Separate process/port isolation → Task 1 (separate app) + Task 7 (separate service, :8080) ✓

**Placeholder scan:** vendored htmx/chart.js in Task 6 is the one area that depends on network at build time — the task explicitly instructs to vendor real copies or note the requirement; not a silent gap.

**Type consistency:** `create_dashboard(config_path, db_path, ollama_url, password, secret, client=None)` is the single factory used by every test; `app.state.logged_in`, `app.state.config_path`, `app.state.db_path`, `app.state.ollama_url`, `app.state.http` are the shared state keys used across tasks. `register_*_routes(app)` is the consistent mounting pattern. `compute_stats(db_path)` and `fetch_since(db_path, last_id, limit)` are the data-layer entry points.
