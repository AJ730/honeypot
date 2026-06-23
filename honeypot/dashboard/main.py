from __future__ import annotations

import os
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from honeypot.dashboard import auth

_TEMPLATES = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))


def create_dashboard(config_path: str, db_path: str, ollama_url: str,
                     password: str, secret: str, client=None) -> FastAPI:
    if not password:
        raise RuntimeError("DASHBOARD_PASSWORD is required")

    _injected_client = client

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if _injected_client is not None:
            app.state.http = _injected_client
        else:
            app.state.http = httpx.AsyncClient(timeout=600)
        yield
        if _injected_client is None:
            await app.state.http.aclose()

    app = FastAPI(lifespan=lifespan)
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
        return _TEMPLATES.TemplateResponse(request, "login.html", {"error": None})

    @app.post("/login")
    async def login(request: Request, password: str = Form(...)):
        if password != app.state.password:
            return _TEMPLATES.TemplateResponse(
                request, "login.html", {"error": "Invalid password"}, status_code=401)
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
        return _TEMPLATES.TemplateResponse(request, "base.html")

    from honeypot.dashboard.config_api import register_config_routes
    register_config_routes(app)

    from honeypot.dashboard.stats import register_stats_routes
    register_stats_routes(app)

    from honeypot.dashboard.feed import register_feed_routes
    register_feed_routes(app)

    from honeypot.dashboard.models_api import register_models_routes
    register_models_routes(app)

    _static_dir = os.path.join(os.path.dirname(__file__), "static")
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")

    return app


_password = os.environ.get("DASHBOARD_PASSWORD", "")
if _password:
    app = create_dashboard(
        os.environ.get("HONEYPOT_CONFIG", "config.yaml"),
        os.environ.get("HONEYPOT_DB", "store.db"),
        os.environ.get("DASHBOARD_OLLAMA_URL", "http://ollama:11500"),
        _password,
        os.environ.get("DASHBOARD_SECRET", "change-me-dev-secret"),
    )
else:
    app = None
