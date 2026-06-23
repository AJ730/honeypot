from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse


def register_models_routes(app) -> None:
    router = APIRouter()

    @router.get("/models", response_class=HTMLResponse)
    async def list_models(request: Request):
        if not app.state.logged_in(request):
            return RedirectResponse("/login", status_code=303)
        resp = await app.state.http.get(f"{app.state.ollama_url}/api/tags")
        data = resp.json()
        models = data.get("models", [])
        return HTMLResponse(_models_table(models))

    @router.post("/models/pull", response_class=HTMLResponse)
    async def pull_model(request: Request, name: str = Form(...)):
        if not app.state.logged_in(request):
            return RedirectResponse("/login", status_code=303)
        resp = await app.state.http.post(
            f"{app.state.ollama_url}/api/pull",
            json={"model": name, "stream": False},
        )
        ok = resp.status_code == 200
        status_msg = resp.json().get("status", "done") if ok else f"error {resp.status_code}"
        html = (
            f'<div id="pull-result">'
            f'<p>Pull <strong>{name}</strong>: {status_msg}</p>'
            f'<p><em>Note: large pulls may take several minutes (v1 is a blocking call — no live progress bar).</em></p>'
            f'</div>'
        )
        return HTMLResponse(html)

    @router.post("/models/delete", response_class=HTMLResponse)
    async def delete_model(request: Request, name: str = Form(...)):
        if not app.state.logged_in(request):
            return RedirectResponse("/login", status_code=303)
        await app.state.http.request(
            "DELETE",
            f"{app.state.ollama_url}/api/delete",
            json={"model": name},
        )
        # Return refreshed list
        resp = await app.state.http.get(f"{app.state.ollama_url}/api/tags")
        data = resp.json()
        models = data.get("models", [])
        return HTMLResponse(_models_table(models))

    app.include_router(router)


def _models_table(models: list) -> str:
    rows = "".join(
        f"<tr><td>{m.get('name', '')}</td></tr>" for m in models
    )
    return (
        f'<table id="models-table">'
        f'<thead><tr><th>Model</th></tr></thead>'
        f'<tbody>{rows}</tbody>'
        f'</table>'
    )
