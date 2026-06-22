import yaml
from starlette.testclient import TestClient
from honeypot.dashboard.main import create_dashboard

GOOD = ("fake_pct: 30\nreal_ollama_url: \"http://127.0.0.1:11500\"\n"
        "default_model: \"qwen2.5:7b\"\nadvertised_models: [\"qwen2.5:7b\"]\n"
        "versions: [\"0.12.6\"]\nguardrail_patterns: [\"phishing\"]\n"
        "fake_responses: [\"hi\"]\nmax_body_bytes: 65536\n")


def build(tmp_path):
    cfg = tmp_path / "config.yaml"; cfg.write_text(GOOD)
    app = create_dashboard(str(cfg), str(tmp_path / "store.db"),
                           "http://ollama:11500", password="s", secret="k")
    return app, cfg


def login(c):
    c.post("/login", data={"password": "s"})


def test_get_config_requires_login(tmp_path):
    app, _ = build(tmp_path)
    with TestClient(app) as c:
        r = c.get("/config", follow_redirects=False)
    assert r.status_code in (302, 303)


def test_get_config_returns_yaml(tmp_path):
    app, _ = build(tmp_path)
    with TestClient(app) as c:
        login(c)
        r = c.get("/config")
    assert r.status_code == 200
    assert "fake_pct" in r.text


def test_post_valid_config_writes_file(tmp_path):
    app, cfg = build(tmp_path)
    new = GOOD.replace("fake_pct: 30", "fake_pct: 55")
    with TestClient(app) as c:
        login(c)
        r = c.post("/config", data={"yaml_text": new})
    assert r.status_code == 200
    assert yaml.safe_load(cfg.read_text())["fake_pct"] == 55


def test_post_invalid_config_rejected_and_file_unchanged(tmp_path):
    app, cfg = build(tmp_path)
    before = cfg.read_text()
    with TestClient(app) as c:
        login(c)
        r = c.post("/config", data={"yaml_text": "fake_pct: 30\nmissing: everything\n"})
    assert r.status_code == 400
    assert cfg.read_text() == before  # untouched
