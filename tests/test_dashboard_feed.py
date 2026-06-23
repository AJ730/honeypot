from honeypot.logging_store import LoggingStore
from honeypot.dashboard.feed import fetch_since, fetch_recent


def test_fetch_recent_returns_last_n_ascending(tmp_path):
    db = str(tmp_path / "store.db")
    s = LoggingStore(db, str(tmp_path / "events.jsonl"))
    for i in range(10):
        s.log({"source_ip": "1.1.1.%d" % i, "endpoint": "/api/version", "routed": "fake"})
    rows = fetch_recent(db, limit=3)
    assert [r["source_ip"] for r in rows] == ["1.1.1.7", "1.1.1.8", "1.1.1.9"]


def test_fetch_recent_missing_db(tmp_path):
    assert fetch_recent(str(tmp_path / "nope.db")) == []


def test_fetch_since(tmp_path):
    db = str(tmp_path / "store.db")
    s = LoggingStore(db, str(tmp_path / "events.jsonl"))
    for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]:
        s.log({"source_ip": ip, "endpoint": "/api/version", "routed": "fake"})
    rows = fetch_since(db, last_id=1)
    assert [r["source_ip"] for r in rows] == ["2.2.2.2", "3.3.3.3"]
    assert all(r["id"] > 1 for r in rows)


def test_fetch_since_missing_db(tmp_path):
    """fetch_since must return [] when db does not exist."""
    rows = fetch_since(str(tmp_path / "nonexistent.db"), last_id=0)
    assert rows == []


def test_fetch_since_empty_db(tmp_path):
    """fetch_since must return [] when last_id exceeds all rows."""
    db = str(tmp_path / "store.db")
    s = LoggingStore(db, str(tmp_path / "events.jsonl"))
    s.log({"source_ip": "1.1.1.1", "endpoint": "/api/version", "routed": "fake"})
    rows = fetch_since(db, last_id=9999)
    assert rows == []


def test_feed_route_requires_login(tmp_path):
    """GET /feed must redirect to /login when not authenticated."""
    from starlette.testclient import TestClient
    from honeypot.dashboard.main import create_dashboard

    cfg = tmp_path / "config.yaml"
    cfg.write_text("fake_pct: 30\n")
    app = create_dashboard(str(cfg), str(tmp_path / "store.db"),
                           "http://ollama:11500", password="secret", secret="k")
    with TestClient(app, raise_server_exceptions=True) as c:
        r = c.get("/feed", follow_redirects=False)
    assert r.status_code in (302, 303)
    assert "/login" in r.headers["location"]


