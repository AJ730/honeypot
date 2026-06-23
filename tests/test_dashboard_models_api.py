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


def test_xss_in_model_name_is_escaped(tmp_path):
    """Model names from Ollama containing HTML tags must be escaped in the list."""
    import httpx as _httpx

    xss_name = "<script>x</script>"

    def xss_handler(request):
        if request.url.path == "/api/tags":
            return _httpx.Response(200, json={"models": [{"name": xss_name}]})
        return _httpx.Response(404)

    cfg = tmp_path / "config.yaml"
    cfg.write_text("fake_pct: 30\n")
    from honeypot.dashboard.main import create_dashboard
    xss_client = _httpx.AsyncClient(transport=_httpx.MockTransport(xss_handler))
    xss_app = create_dashboard(str(cfg), str(tmp_path / "store.db"),
                               "http://ollama:11500", password="s", secret="k",
                               client=xss_client)
    with TestClient(xss_app) as c:
        c.post("/login", data={"password": "s"})
        r = c.get("/models")
    assert r.status_code == 200
    assert "<script>" not in r.text
    assert "&lt;script&gt;" in r.text


def test_xss_in_pull_name_is_escaped(tmp_path):
    """User-supplied model name echoed in pull result must be HTML-escaped."""
    with TestClient(build(tmp_path)) as c:
        login(c)
        r = c.post("/models/pull", data={"name": "<script>alert(1)</script>"})
    assert r.status_code == 200
    assert "<script>" not in r.text
    assert "&lt;script&gt;" in r.text
