from __future__ import annotations

import json
import os
import random
import time

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from honeypot.config import ConfigStore
from honeypot.logging_store import LoggingStore
from honeypot import fakes, guardrails
from honeypot.router import should_fake, extract_prompt
from honeypot.proxy import forward_json, stream_generate


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _now_ts() -> str:
    """Per-call UTC timestamp in Ollama's microsecond format."""
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond:06d}Z"


def _trailer_fields() -> dict:
    """Plausible random trailer numeric fields matching real Ollama non-stream responses."""
    return {
        "total_duration": random.randint(500_000_000, 8_000_000_000),
        "load_duration": random.randint(10_000_000, 500_000_000),
        "prompt_eval_count": random.randint(5, 64),
        "eval_count": random.randint(10, 256),
        "eval_duration": random.randint(300_000_000, 6_000_000_000),
    }


def _split_words(text: str) -> list[str]:
    """Split text into a small number of word-group pieces for streaming simulation."""
    words = text.split(" ")
    # group into ~3–5 pieces
    n = max(2, min(5, len(words)))
    size = max(1, len(words) // n)
    pieces = []
    for i in range(0, len(words), size):
        chunk = " ".join(words[i:i + size])
        if pieces:
            chunk = " " + chunk  # restore space between groups
        pieces.append(chunk)
    return pieces if pieces else [""]


def _stream_generate_response(model: str, text: str, is_chat: bool):
    """Yield NDJSON bytes simulating an Ollama streaming response."""
    pieces = _split_words(text)
    for piece in pieces:
        if is_chat:
            obj = {
                "model": model,
                "created_at": _now_ts(),
                "message": {"role": "assistant", "content": piece},
                "done": False,
            }
        else:
            obj = {
                "model": model,
                "created_at": _now_ts(),
                "response": piece,
                "done": False,
            }
        yield (json.dumps(obj) + "\n").encode()
    # Final done object
    trailer = _trailer_fields()
    if is_chat:
        final = {
            "model": model,
            "created_at": _now_ts(),
            "message": {"role": "assistant", "content": ""},
            "done": True,
            "done_reason": "stop",
        }
    else:
        final = {
            "model": model,
            "created_at": _now_ts(),
            "response": "",
            "done": True,
            "done_reason": "stop",
        }
    final.update(trailer)
    yield (json.dumps(final) + "\n").encode()


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

    # FIX 4 — Remove the `server` header from every response
    @app.middleware("http")
    async def _strip_server(request, call_next):
        resp = await call_next(request)
        if "server" in resp.headers:
            del resp.headers["server"]
        return resp

    # FIX 3 — Ollama-style 404/405 plain text instead of FastAPI JSON errors
    @app.exception_handler(StarletteHTTPException)
    async def _ollama_errors(request, exc):
        if exc.status_code == 404:
            return PlainTextResponse("404 page not found", status_code=404)
        if exc.status_code == 405:
            return PlainTextResponse("405 method not allowed", status_code=405)
        return PlainTextResponse(str(exc.detail), status_code=exc.status_code)

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

        parsed, err = _parse_body(body)
        if err is not None:
            record(request, body, model=None, routed="fake", response_status=400)
            return err

        model = parsed.get("model", cfg.default_model)
        prompt = extract_prompt(parsed)
        ip = request.client.host if request.client else "0.0.0.0"

        # FIX 1: determine streaming (absent → True, Ollama default)
        stream = parsed.get("stream", True)
        do_stream = stream is not False  # only False (the boolean) disables streaming

        # Fast keyword pre-filter first (instant, no model call), then the LLM
        # safety classifier if enabled. The LLM check fails open (returns None)
        # so a slow/missing classifier never takes the honeypot down.
        trip = guardrails.check(prompt, cfg.guardrail_patterns)
        if trip is None and getattr(cfg, "llm_guard_enabled", False):
            trip = await guardrails.llm_check(
                state["client"], cfg.real_ollama_url,
                getattr(cfg, "llm_guard_model", "llama-guard3:1b"), prompt,
            )
        if trip is not None:
            if is_chat:
                refusal_data = guardrails.refusal_chat_response(model)
                text = refusal_data["message"]["content"]
            else:
                refusal_data = guardrails.refusal_response(model)
                text = refusal_data["response"]

            record(request, body, model=model, routed="blocked", guardrail_trip=trip, response_status=200)

            if do_stream:
                return StreamingResponse(
                    _stream_generate_response(model, text, is_chat),
                    media_type="application/x-ndjson",
                )
            else:
                refusal_data.update(_trailer_fields())
                return JSONResponse(refusal_data, media_type="application/json")

        if should_fake(ip, prompt, cfg.fake_pct):
            fake_data = fakes.fake_completion(parsed, cfg.fake_responses)
            text = fake_data["response"]

            record(request, body, model=model, routed="fake", response_status=200)

            if do_stream:
                return StreamingResponse(
                    _stream_generate_response(model, text, is_chat),
                    media_type="application/x-ndjson",
                )
            else:
                if is_chat:
                    single = {
                        "model": model,
                        "created_at": fake_data["created_at"],
                        "message": {"role": "assistant", "content": text},
                        "done": True,
                        "done_reason": "stop",
                    }
                else:
                    single = fake_data
                single.update(_trailer_fields())
                return JSONResponse(single, media_type="application/json")

        # FIX 2: real path — branch on stream flag
        if not do_stream:
            # Non-streaming: forward as a single JSON call
            t0 = time.time()
            status, data = await forward_json(state["client"], cfg.real_ollama_url, request.url.path, "POST", body)
            record(request, body, model=model, routed="real",
                   response_status=status, latency_ms=int((time.time() - t0) * 1000))
            return JSONResponse(data, status_code=status, media_type="application/json")
        else:
            # Streaming: log once then stream
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


app = create_app(
    os.environ.get("HONEYPOT_CONFIG", "config.yaml"),
    os.environ.get("HONEYPOT_DB", "store.db"),
    os.environ.get("HONEYPOT_JSONL", "events.jsonl"),
)
