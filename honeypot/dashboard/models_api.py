from __future__ import annotations

import html

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse


def register_models_routes(app) -> None:
    router = APIRouter()

    async def _list() -> list:
        resp = await app.state.http.get(f"{app.state.ollama_url}/api/tags")
        return resp.json().get("models", [])

    @router.get("/models", response_class=HTMLResponse)
    async def list_models(request: Request):
        if not app.state.logged_in(request):
            return RedirectResponse("/login", status_code=303)
        try:
            models = await _list()
        except Exception as exc:
            return HTMLResponse(_error("Couldn't reach the model backend", exc))
        return HTMLResponse(_models_table(models))

    @router.post("/models/pull", response_class=HTMLResponse)
    async def pull_model(request: Request, name: str = Form(...)):
        if not app.state.logged_in(request):
            return RedirectResponse("/login", status_code=303)
        name = name.strip()
        if not name:
            return HTMLResponse(_pull_result("", "Enter a model name first.", ok=False))
        try:
            resp = await app.state.http.post(
                f"{app.state.ollama_url}/api/pull",
                json={"model": name, "stream": False},
            )
            ok = resp.status_code == 200
            try:
                status_msg = resp.json().get("status", "done")
            except Exception:
                status_msg = "done" if ok else f"error {resp.status_code}"
        except Exception as exc:
            return HTMLResponse(_pull_result(name, f"backend error: {exc}", ok=False))
        return HTMLResponse(_pull_result(name, status_msg, ok=ok))

    @router.post("/models/delete", response_class=HTMLResponse)
    async def delete_model(request: Request, name: str = Form(...)):
        if not app.state.logged_in(request):
            return RedirectResponse("/login", status_code=303)
        try:
            await app.state.http.request(
                "DELETE", f"{app.state.ollama_url}/api/delete",
                json={"model": name},
            )
            models = await _list()
        except Exception as exc:
            return HTMLResponse(_error("Delete failed", exc))
        return HTMLResponse(_models_table(models))

    app.include_router(router)


def _human_size(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _models_table(models: list) -> str:
    if not models:
        return ('<p class="empty">No models installed. Pull one above '
                '(e.g. <code>qwen2.5:3b</code>) to get started.</p>')
    rows = []
    for m in models:
        name = html.escape(m.get("name", ""))
        details = m.get("details") or {}
        params = html.escape(str(details.get("parameter_size", "")))
        quant = html.escape(str(details.get("quantization_level", "")))
        size = _human_size(m.get("size"))
        rows.append(
            f'<tr><td class="mono strong">{name}</td>'
            f'<td class="mono">{params}</td>'
            f'<td class="mono dim">{quant}</td>'
            f'<td class="mono num">{size}</td>'
            f'<td><button class="btn-danger" hx-post="/models/delete" '
            f'hx-vals=\'{{"name": "{name}"}}\' hx-target="#models-panel" '
            f'hx-confirm="Delete {name} from the backend?">Delete</button></td></tr>'
        )
    return (
        '<table class="data"><thead><tr>'
        '<th>Model</th><th>Params</th><th>Quant</th><th class="num">Size</th><th></th>'
        '</tr></thead><tbody>' + "".join(rows) + '</tbody></table>'
    )


def _pull_result(name: str, msg: str, ok: bool) -> str:
    cls = "ok" if ok else "err"
    label = html.escape(name) if name else ""
    head = f'Pull <strong class="mono">{label}</strong>: ' if label else ""
    return (
        f'<div class="notice {cls}">{head}{html.escape(msg)}</div>'
        f'<div hx-get="/models" hx-trigger="load delay:500ms" hx-target="#models-list"></div>'
    )


def _error(headline: str, exc: Exception) -> str:
    return f'<div class="notice err">{html.escape(headline)}: {html.escape(str(exc))}</div>'
