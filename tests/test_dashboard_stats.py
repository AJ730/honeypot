from honeypot.logging_store import LoggingStore
from honeypot.dashboard.stats import compute_stats


def seed(tmp_path):
    db = str(tmp_path / "store.db")
    s = LoggingStore(db, str(tmp_path / "events.jsonl"))
    rows = [
        {"ts": "2026-06-22T10:00:00Z", "source_ip": "1.1.1.1", "endpoint": "/api/generate", "routed": "real", "model": "qwen2.5:7b"},
        {"ts": "2026-06-22T10:01:00Z", "source_ip": "1.1.1.1", "endpoint": "/api/generate", "routed": "fake", "model": "qwen2.5:3b"},
        {"ts": "2026-06-22T11:00:00Z", "source_ip": "2.2.2.2", "endpoint": "/api/version", "routed": "fake", "version_served": "0.11.4"},
        {"ts": "2026-06-22T11:05:00Z", "source_ip": "2.2.2.2", "endpoint": "/api/generate", "routed": "blocked", "guardrail_trip": "write malware", "model": "qwen2.5:7b"},
    ]
    for r in rows:
        s.log(r)
    return db


def test_compute_stats(tmp_path):
    db = seed(tmp_path)
    st = compute_stats(db)
    assert st["total_requests"] == 4
    assert st["by_routed"]["fake"] == 2
    assert st["by_routed"]["blocked"] == 1
    top = {d["source_ip"]: d["count"] for d in st["top_source_ips"]}
    assert top["1.1.1.1"] == 2
    trips = {d["reason"]: d["count"] for d in st["guardrail_trips"]}
    assert trips["write malware"] == 1
    models = {d["model"]: d["count"] for d in st["model_preference"]}
    assert models["qwen2.5:7b"] == 2


def test_compute_stats_missing_db(tmp_path):
    """compute_stats must not raise when db file doesn't exist."""
    st = compute_stats(str(tmp_path / "nonexistent.db"))
    assert st["total_requests"] == 0
    assert st["by_routed"] == {"real": 0, "fake": 0, "blocked": 0}
    assert st["top_source_ips"] == []


def test_stats_route_requires_login(tmp_path):
    """GET /stats must redirect to /login when not authenticated."""
    from starlette.testclient import TestClient
    from honeypot.dashboard.main import create_dashboard

    cfg = tmp_path / "config.yaml"
    cfg.write_text("fake_pct: 30\n")
    app = create_dashboard(str(cfg), str(tmp_path / "store.db"),
                           "http://ollama:11500", password="secret", secret="k")
    with TestClient(app) as c:
        r = c.get("/stats", follow_redirects=False)
    assert r.status_code in (302, 303)
    assert "/login" in r.headers["location"]


def test_stats_route_returns_json(tmp_path):
    """GET /stats returns JSON dict when logged in."""
    from starlette.testclient import TestClient
    from honeypot.dashboard.main import create_dashboard

    db = seed(tmp_path)
    cfg = tmp_path / "config.yaml"
    cfg.write_text("fake_pct: 30\n")
    app = create_dashboard(str(cfg), db, "http://ollama:11500",
                           password="secret", secret="k")
    with TestClient(app) as c:
        c.post("/login", data={"password": "secret"}, follow_redirects=False)
        r = c.get("/stats")
    assert r.status_code == 200
    data = r.json()
    assert data["total_requests"] == 4
    assert "by_routed" in data
