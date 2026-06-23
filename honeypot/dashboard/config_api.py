from __future__ import annotations

import html
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
        msg = f'<div class="cfg-msg ok">{html.escape(ok)}</div>'
    if err:
        msg = f'<div class="cfg-msg err">Rejected — {html.escape(err)}</div>'
    return (
        f'{msg}<form hx-post="/config" hx-target="#config-panel" hx-swap="innerHTML">'
        f'<textarea name="yaml_text" spellcheck="false">{html.escape(text)}</textarea>'
        f'<button type="submit">Save &amp; reload</button></form>'
    )
