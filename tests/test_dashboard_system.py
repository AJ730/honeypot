from starlette.testclient import TestClient
from honeypot.dashboard.main import create_dashboard
from honeypot.dashboard.system import compute_system


def build(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("fake_pct: 30\n")
    return create_dashboard(str(cfg), str(tmp_path / "store.db"),
                            "http://ollama:11500", password="s", secret="k")


def test_compute_system_shape():
    d = compute_system()
    assert "available" in d and "ts" in d
    if d["available"]:
        # psutil present in test env — core fields should be populated
        assert d["cpu_count"] is None or d["cpu_count"] >= 1
        assert "mem" in d and d["mem"]["total"] > 0
        assert "disk" in d and d["disk"]["total"] > 0


def test_system_route_requires_login(tmp_path):
    with TestClient(build(tmp_path)) as c:
        r = c.get("/system", follow_redirects=False)
    assert r.status_code in (302, 303)


def test_system_route_returns_json(tmp_path):
    with TestClient(build(tmp_path)) as c:
        c.post("/login", data={"password": "s"})
        r = c.get("/system")
    assert r.status_code == 200
    body = r.json()
    assert "available" in body
