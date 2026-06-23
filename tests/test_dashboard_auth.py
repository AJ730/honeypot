from starlette.testclient import TestClient
from honeypot.dashboard.main import create_dashboard


def build(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("fake_pct: 30\n")
    return create_dashboard(str(cfg), str(tmp_path / "store.db"),
                            "http://ollama:11500", password="secret", secret="k")


def test_root_requires_login(tmp_path):
    with TestClient(build(tmp_path)) as c:
        r = c.get("/", follow_redirects=False)
    assert r.status_code in (302, 303)
    assert "/login" in r.headers["location"]


def test_login_wrong_password(tmp_path):
    with TestClient(build(tmp_path)) as c:
        r = c.post("/login", data={"password": "nope"}, follow_redirects=False)
    assert r.status_code == 401 or "/login" in r.headers.get("location", "")


def test_login_then_access(tmp_path):
    with TestClient(build(tmp_path)) as c:
        r = c.post("/login", data={"password": "secret"}, follow_redirects=False)
        assert r.status_code in (302, 303)
        # cookie now set on the client; root should render
        r2 = c.get("/")
    assert r2.status_code == 200


def test_logout_clears_session(tmp_path):
    with TestClient(build(tmp_path)) as c:
        c.post("/login", data={"password": "secret"})
        c.post("/logout")
        r = c.get("/", follow_redirects=False)
    assert r.status_code in (302, 303)
