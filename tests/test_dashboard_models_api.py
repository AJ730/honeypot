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
