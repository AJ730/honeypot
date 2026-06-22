from __future__ import annotations

import json
import time

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from honeypot.config import ConfigStore
from honeypot.logging_store import LoggingStore
from honeypot import fakes, guardrails
from honeypot.router import should_fake, extract_prompt
from honeypot.proxy import forward_json, stream_generate


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _parse_body(body: bytes):
    """Return (parsed_dict, None) on success or (None, JSONResponse) on bad JSON."""
    try:
        return json.loads(body or b"{}"), None
    except (json.JSONDecodeError, ValueError):
        return None, JSONResponse({"error": "invalid character in request body"}, status_code=400)


def create_app(
    config_path: str,
    db_path: str,
    jsonl_path: str,
    client: httpx.AsyncClient | None = None,
) -> FastAPI:
    app = FastAPI()
    cfg_store = ConfigStore(config_path)
    log = LoggingStore(db_path, jsonl_path)
    state = {"client": client}

    @app.on_event("startup")
    async def _startup():
        if state["client"] is None:
            state["client"] = httpx.AsyncClient(timeout=300.0)

    @app.on_event("shutdown")
    async def _shutdown():
        if state["client"] is not None:
            await state["client"].aclose()

    def record(req: Request, body: bytes, **kw):
        cfg = cfg_store.get()
        entry = {
            "ts": _now(),
            "source_ip": req.client.host if req.client else None,
            "dest_ip": req.url.hostname,
            "method": req.method,
            "endpoint": req.url.path,
            "request_body": body[: cfg.max_body_bytes].decode("utf-8", "replace") if body else None,
        }
        entry.update(kw)
        log.log(entry)

    # ---- Real (proxied) endpoints ----
    @app.get("/api/tags")
    @app.get("/api/ps")
    async def real_get(request: Request):
        cfg = cfg_store.get()
        t0 = time.time()
        status, data = await forward_json(state["client"], cfg.real_ollama_url, request.url.path, "GET", None)
        record(request, b"", routed="real", response_status=status, latency_ms=int((time.time() - t0) * 1000))
        return JSONResponse(data, status_code=status)

    @app.post("/api/show")
    async def real_show(request: Request):
        cfg = cfg_store.get()
        body = await request.body()
        t0 = time.time()
        status, data = await forward_json(state["client"], cfg.real_ollama_url, "/api/show", "POST", body)
        record(request, body, routed="real", response_status=status, latency_ms=int((time.time() - t0) * 1000))
        return JSONResponse(data, status_code=status)

    # ---- Faked static/template endpoints ----
    @app.get("/api/version")
    async def version(request: Request):
        cfg = cfg_store.get()
        ip = request.client.host if request.client else "0.0.0.0"
        v = fakes.fake_version(ip, cfg.versions)
        record(request, b"", routed="fake", response_status=200, version_served=v)
        return JSONResponse({"version": v})

    @app.post("/api/embed")
    async def embed(request: Request):
        body = await request.body()
        parsed, err = _parse_body(body)
        if err is not None:
            record(request, body, routed="fake", response_status=400)
            return err
        data = fakes.fake_embed(parsed)
        record(request, body, routed="fake", response_status=200)
        return JSONResponse(data)

    @app.post("/api/create")
    async def create(request: Request):
        body = await request.body()
        record(request, body, routed="fake", response_status=200)
        return JSONResponse(fakes.CREATE_RESPONSE)

    @app.post("/api/pull")
    async def pull(request: Request):
        body = await request.body()
        record(request, body, routed="fake", response_status=200)
        return JSONResponse(fakes.PULL_RESPONSE)

    @app.post("/api/push")
    async def push(request: Request):
        body = await request.body()
        record(request, body, routed="fake", response_status=200)
        return JSONResponse(fakes.PUSH_RESPONSE)

    @app.post("/api/copy")
    async def copy(request: Request):
        body = await request.body()
        record(request, body, routed="fake", response_status=200)
        return Response(status_code=200)

    @app.api_route("/api/delete", methods=["DELETE"])
    async def delete(request: Request):
        body = await request.body()
        record(request, body, routed="fake", response_status=200)
        return Response(content=fakes.DELETE_OK, status_code=200)

    # ---- generate / chat: guardrail -> fake/real ----
    async def _handle_generate(request: Request, is_chat: bool):
        cfg = cfg_store.get()
        body = await request.body()

        # FIX 2: gracefully handle malformed JSON
        parsed, err = _parse_body(body)
        if err is not None:
            record(request, body, model=None, routed="fake", response_status=400)
            return err

        model = parsed.get("model", cfg.default_model)
        prompt = extract_prompt(parsed)
        ip = request.client.host if request.client else "0.0.0.0"

        trip = guardrails.check(prompt, cfg.guardrail_patterns)
        if trip is not None:
            data = guardrails.refusal_chat_response(model) if is_chat else guardrails.refusal_response(model)
            record(request, body, model=model, routed="blocked", guardrail_trip=trip, response_status=200)
            return JSONResponse(data)

        if should_fake(ip, prompt, cfg.fake_pct):
            data = fakes.fake_completion(parsed, cfg.fake_responses)
            if is_chat:
                data = {"model": model, "created_at": data["created_at"],
                        "message": {"role": "assistant", "content": data["response"]},
                        "done": True, "done_reason": "stop"}
            record(request, body, model=model, routed="fake", response_status=200)
            return JSONResponse(data)

        # FIX 1: log with response_status=None and latency_ms=None since the
        # actual status and latency are unknown until the upstream stream completes.
        record(request, body, model=model, routed="real", response_status=None, latency_ms=None)
        gen = stream_generate(state["client"], cfg.real_ollama_url, request.url.path, body)
        return StreamingResponse(gen, media_type="application/x-ndjson")

    @app.post("/api/generate")
    async def generate(request: Request):
        return await _handle_generate(request, is_chat=False)

    @app.post("/api/chat")
    async def chat(request: Request):
        return await _handle_generate(request, is_chat=True)

    return app


app = create_app("config.yaml", "store.db", "events.jsonl")
