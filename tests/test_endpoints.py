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
        return httpx.Response(200, content=b'{"response":"real","done":true}\n')
    return httpx.Response(200, json={"ok": True})


def build(tmp_path, fake_pct=0):
    cfg = write_config(tmp_path, fake_pct)
    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    app = create_app(str(cfg), str(tmp_path / "store.db"),
                     str(tmp_path / "events.jsonl"), client=client)
    return app


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
