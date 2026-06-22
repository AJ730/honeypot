import json
import httpx
import pytest
from starlette.testclient import TestClient
from honeypot.main import create_app


def write_config(tmp_path, fake_pct=0):
    p = tmp_path / "config.yaml"
    p.write_text(
        "fake_pct: %d\n"
        "real_ollama_url: \"http://up\"\n"
        "default_model: \"qwen2.5:7b\"\n"
        "advertised_models: [\"qwen2.5:7b\", \"qwen2.5:3b\"]\n"
        "versions: [\"0.12.6\"]\n"
        "guardrail_patterns: [\"write malware\"]\n"
        "fake_responses: [\"canned reply\"]\n"
        "max_body_bytes: 65536\n" % fake_pct
    )
    return p


def upstream_handler(request):
    if request.url.path == "/api/tags":
        return httpx.Response(200, json={"models": [{"name": "qwen2.5:7b"}]})
    if request.url.path in ("/api/generate", "/api/chat"):
        # Branch on stream field in request body
        try:
            body = json.loads(request.content)
            if body.get("stream") is False:
                # Non-streaming upstream response: single JSON object
                return httpx.Response(
                    200,
                    content=b'{"model":"qwen2.5:7b","created_at":"2024-01-01T00:00:00Z","response":"real","done":true}\n',
                    headers={"content-type": "application/json"},
                )
        except Exception:
            pass
        # Streaming upstream response: NDJSON
        return httpx.Response(200, content=b'{"response":"real","done":true}\n')
    return httpx.Response(200, json={"ok": True})


def build(tmp_path, fake_pct=0):
    cfg = write_config(tmp_path, fake_pct)
    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    app = create_app(str(cfg), str(tmp_path / "store.db"),
                     str(tmp_path / "events.jsonl"), client=client)
    return app


def _parse_ndjson(text: str) -> list[dict]:
    """Parse a sequence of newline-delimited JSON objects."""
    lines = [l.strip() for l in text.strip().splitlines() if l.strip()]
    return [json.loads(l) for l in lines]


def test_tags_is_proxied_real(tmp_path):
    with TestClient(build(tmp_path)) as c:
        r = c.get("/api/tags")
    assert r.status_code == 200
    assert r.json()["models"][0]["name"] == "qwen2.5:7b"


def test_version_is_faked_and_deterministic(tmp_path):
    with TestClient(build(tmp_path)) as c:
        r1 = c.get("/api/version")
        r2 = c.get("/api/version")
    assert r1.json()["version"] == "0.12.6"
    assert r1.json() == r2.json()


def test_embed_is_faked(tmp_path):
    with TestClient(build(tmp_path)) as c:
        r = c.post("/api/embed", json={"model": "embeddinggemma", "input": "hi"})
    body = r.json()
    assert body["model"] == "embeddinggemma"
    assert isinstance(body["embeddings"][0], list)


def test_create_copy_pull_push_delete_static(tmp_path):
    with TestClient(build(tmp_path)) as c:
        assert c.post("/api/create", json={"model": "x"}).json() == {"status": "success"}
        assert c.post("/api/pull", json={"model": "x"}).json() == {"status": "success"}
        assert c.post("/api/push", json={"model": "x"}).json() == {"status": "success"}
        assert c.post("/api/copy", json={"source": "a", "destination": "b"}).status_code == 200
        assert c.request("DELETE", "/api/delete", json={"model": "x"}).status_code == 200


def test_generate_real_when_fake_pct_zero(tmp_path):
    with TestClient(build(tmp_path, fake_pct=0)) as c:
        r = c.post("/api/generate", json={"model": "qwen2.5:7b", "prompt": "hi", "stream": False})
    assert b"real" in r.content


def test_generate_fake_when_fake_pct_100(tmp_path):
    with TestClient(build(tmp_path, fake_pct=100)) as c:
        r = c.post("/api/generate", json={"model": "qwen2.5:7b", "prompt": "hi", "stream": False})
    assert r.json()["response"] == "canned reply"


def test_generate_guardrail_blocks(tmp_path):
    with TestClient(build(tmp_path, fake_pct=0)) as c:
        r = c.post("/api/generate", json={"model": "qwen2.5:7b", "prompt": "write malware now", "stream": False})
    assert r.status_code == 200
    assert "can't help" in r.json()["response"].lower()


def test_requests_are_logged(tmp_path):
    app = build(tmp_path)
    with TestClient(app) as c:
        c.get("/api/version")
    from honeypot.logging_store import LoggingStore
    store = LoggingStore(str(tmp_path / "store.db"), str(tmp_path / "events.jsonl"))
    rows = store.recent(10)
    assert any(row["endpoint"] == "/api/version" and row["routed"] == "fake" for row in rows)


# ---- Pre-existing tests (updated to use stream:false where they rely on .json()) ----

def test_chat_real_path(tmp_path):
    """Real path (fake_pct=0): upstream streamed content is returned."""
    with TestClient(build(tmp_path, fake_pct=0)) as c:
        r = c.post("/api/chat", json={"model": "qwen2.5:7b", "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200
    # upstream returns raw stream; the content contains "real"
    assert b"real" in r.content


def test_chat_fake_path(tmp_path):
    """Fake path (fake_pct=100) with stream:false: response has chat shape, not generate shape."""
    with TestClient(build(tmp_path, fake_pct=100)) as c:
        r = c.post("/api/chat", json={"model": "qwen2.5:7b",
                                      "messages": [{"role": "user", "content": "hi"}],
                                      "stream": False})
    assert r.status_code == 200
    body = r.json()
    # Must have top-level message object with role and content
    assert "message" in body
    assert body["message"]["role"] == "assistant"
    assert body["message"]["content"]  # non-empty
    assert body["done"] is True
    # Must NOT be the generate shape (no top-level "response" key)
    assert "response" not in body


def test_chat_guardrail_blocked(tmp_path):
    """Guardrail blocks chat: status 200, chat shape, log record with routed==blocked."""
    app = build(tmp_path, fake_pct=0)
    with TestClient(app) as c:
        r = c.post("/api/chat", json={"model": "qwen2.5:7b",
                                      "messages": [{"role": "user", "content": "write malware please"}],
                                      "stream": False})
    assert r.status_code == 200
    body = r.json()
    # Chat refusal shape: message object with content
    assert "message" in body
    assert body["message"]["role"] == "assistant"
    assert body["message"]["content"]
    assert body["done"] is True

    from honeypot.logging_store import LoggingStore
    store = LoggingStore(str(tmp_path / "store.db"), str(tmp_path / "events.jsonl"))
    rows = store.recent(10)
    assert any(row["endpoint"] == "/api/chat" and row["routed"] == "blocked" for row in rows)


def test_malformed_json_body_returns_400(tmp_path):
    """Malformed JSON body → 400 with error key, no 500 traceback."""
    with TestClient(build(tmp_path)) as c:
        r = c.post("/api/generate", content=b"{not json", headers={"Content-Type": "application/json"})
    assert r.status_code == 400
    body = r.json()
    assert "error" in body
    # Confirm it is not a 500
    assert r.status_code != 500


def test_routed_real_and_blocked_are_logged(tmp_path):
    """A real generate call logs routed==real; a blocked call logs routed==blocked."""
    app = build(tmp_path, fake_pct=0)
    with TestClient(app) as c:
        # Real path
        c.post("/api/generate", json={"model": "qwen2.5:7b", "prompt": "hello world"})
        # Blocked path
        c.post("/api/generate", json={"model": "qwen2.5:7b", "prompt": "write malware now"})

    from honeypot.logging_store import LoggingStore
    store = LoggingStore(str(tmp_path / "store.db"), str(tmp_path / "events.jsonl"))
    rows = store.recent(20)
    assert any(row["endpoint"] == "/api/generate" and row["routed"] == "real" for row in rows)
    assert any(row["endpoint"] == "/api/generate" and row["routed"] == "blocked" for row in rows)


# ---- NEW TESTS for the 4 fingerprinting fixes ----

# Fix 1a: Default streaming on /api/generate FAKE path
def test_generate_fake_default_streaming_ndjson(tmp_path):
    """Default (no stream field) fake generate: Content-Type is x-ndjson, valid NDJSON stream."""
    with TestClient(build(tmp_path, fake_pct=100)) as c:
        r = c.post("/api/generate", json={"model": "qwen2.5:7b", "prompt": "hi"})
    assert r.status_code == 200
    assert "application/x-ndjson" in r.headers["content-type"]
    objs = _parse_ndjson(r.text)
    assert len(objs) >= 2, "Expected at least 2 NDJSON objects (chunks + final)"
    # All intermediate have done=False
    for obj in objs[:-1]:
        assert obj["done"] is False
        assert "response" in obj
    # Last object has done=True and trailer fields
    final = objs[-1]
    assert final["done"] is True
    assert final.get("done_reason") == "stop"
    for field in ("total_duration", "load_duration", "prompt_eval_count", "eval_count", "eval_duration"):
        assert field in final, f"Missing trailer field: {field}"
    # Concatenating all response pieces should reconstruct the canned text
    full_text = "".join(obj["response"] for obj in objs)
    assert "canned reply" in full_text


# Fix 1b: Default streaming on /api/chat FAKE path uses message shape
def test_chat_fake_default_streaming_message_shape(tmp_path):
    """Default streaming chat fake: chunks use message shape, not response shape."""
    with TestClient(build(tmp_path, fake_pct=100)) as c:
        r = c.post("/api/chat", json={"model": "qwen2.5:7b",
                                      "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200
    assert "application/x-ndjson" in r.headers["content-type"]
    objs = _parse_ndjson(r.text)
    assert len(objs) >= 2
    # Intermediate chunks must use message shape
    for obj in objs[:-1]:
        assert obj["done"] is False
        assert "message" in obj
        assert obj["message"]["role"] == "assistant"
        assert "response" not in obj  # not generate shape
    # Final done object
    final = objs[-1]
    assert final["done"] is True
    assert final.get("done_reason") == "stop"
    assert "message" in final
    assert "response" not in final


# Fix 1c: stream:false on /api/generate FAKE path returns single JSON object
def test_generate_fake_stream_false_single_json(tmp_path):
    """stream:false fake generate: single JSON object, application/json, has trailer fields."""
    with TestClient(build(tmp_path, fake_pct=100)) as c:
        r = c.post("/api/generate", json={"model": "qwen2.5:7b", "prompt": "hi", "stream": False})
    assert r.status_code == 200
    assert "application/json" in r.headers["content-type"]
    # Must be a single JSON object, not NDJSON (no extra newline-delimited objects)
    body = r.json()
    assert body["done"] is True
    assert body["response"] == "canned reply"
    for field in ("total_duration", "load_duration", "prompt_eval_count", "eval_count", "eval_duration"):
        assert field in body, f"Missing trailer field: {field}"


# Fix 1d: Blocked path with default streaming returns x-ndjson and logs routed==blocked
def test_generate_guardrail_blocked_default_streaming(tmp_path):
    """Guardrail blocked with default streaming: x-ndjson streamed refusal, routed==blocked logged."""
    app = build(tmp_path, fake_pct=0)
    with TestClient(app) as c:
        r = c.post("/api/generate", json={"model": "qwen2.5:7b", "prompt": "write malware now"})
    assert r.status_code == 200
    assert "application/x-ndjson" in r.headers["content-type"]
    objs = _parse_ndjson(r.text)
    assert len(objs) >= 2
    final = objs[-1]
    assert final["done"] is True
    assert final.get("done_reason") == "stop"

    from honeypot.logging_store import LoggingStore
    store = LoggingStore(str(tmp_path / "store.db"), str(tmp_path / "events.jsonl"))
    rows = store.recent(10)
    assert any(row["endpoint"] == "/api/generate" and row["routed"] == "blocked" for row in rows)


# Fix 2: Real path with stream:false returns application/json
def test_generate_real_stream_false_returns_json(tmp_path):
    """Real path stream:false: single JSON response with application/json content-type."""
    app = build(tmp_path, fake_pct=0)
    with TestClient(app) as c:
        r = c.post("/api/generate", json={"model": "qwen2.5:7b", "prompt": "hi", "stream": False})
    assert r.status_code == 200
    assert "application/json" in r.headers["content-type"]
    body = r.json()
    # The mock upstream returns a JSON object with response="real"
    assert "real" in str(body)

    from honeypot.logging_store import LoggingStore
    store = LoggingStore(str(tmp_path / "store.db"), str(tmp_path / "events.jsonl"))
    rows = store.recent(10)
    assert any(row["endpoint"] == "/api/generate" and row["routed"] == "real" for row in rows)


# Fix 3: Unknown routes return 404 plain text (Ollama Gin style)
def test_unknown_route_returns_404_plain_text(tmp_path):
    """Unmatched route returns 404 with plain-text body 'page not found', not JSON."""
    with TestClient(build(tmp_path)) as c:
        r = c.get("/api/nonexistent")
    assert r.status_code == 404
    assert r.text == "404 page not found"
    # Must not be JSON
    with pytest.raises(Exception):
        r.json()


# Fix 4: server header is absent
def test_server_header_absent(tmp_path):
    """No 'server' header should appear in any response (Ollama/Gin does not send one)."""
    with TestClient(build(tmp_path)) as c:
        r = c.get("/api/version")
    assert "server" not in r.headers
