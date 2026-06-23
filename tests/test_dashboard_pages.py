from starlette.testclient import TestClient
from honeypot.dashboard.main import create_dashboard


def build(tmp_path):
    cfg = tmp_path / "config.yaml"; cfg.write_text("fake_pct: 30\n")
    return create_dashboard(str(cfg), str(tmp_path / "store.db"),
                            "http://ollama:11500", password="s", secret="k")


def test_dashboard_page_has_panels(tmp_path):
    with TestClient(build(tmp_path)) as c:
        c.post("/login", data={"password": "s"})
        r = c.get("/")
    assert r.status_code == 200
    for needle in ["Config", "Models", "Live", "Analytics", "/static/app.js"]:
        assert needle in r.text


def test_static_served(tmp_path):
    with TestClient(build(tmp_path)) as c:
        c.post("/login", data={"password": "s"})
        r = c.get("/static/app.js")
    assert r.status_code == 200
