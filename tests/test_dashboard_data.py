from starlette.testclient import TestClient
from honeypot.logging_store import LoggingStore
from honeypot.dashboard.main import create_dashboard
from honeypot.dashboard.data_api import clear_data


def test_clear_data_wipes_both_sinks(tmp_path):
    db = str(tmp_path / "store.db")
    jsonl = str(tmp_path / "events.jsonl")
    s = LoggingStore(db, jsonl)
    for ip in ["1.1.1.1", "2.2.2.2"]:
        s.log({"source_ip": ip, "endpoint": "/api/version", "routed": "fake"})
    s.log_scan("9.9.9.9", 22)
    s.log_scan("9.9.9.9", 8080)
    assert s._conn.execute("select count(*) from requests").fetchone()[0] == 2
    assert s._conn.execute("select count(*) from scans").fetchone()[0] == 2
    clear_data(db, jsonl)
    assert s._conn.execute("select count(*) from requests").fetchone()[0] == 0
    assert s._conn.execute("select count(*) from scans").fetchone()[0] == 0
    assert (tmp_path / "events.jsonl").read_text() == ""


def test_clear_route_requires_login(tmp_path):
    cfg = tmp_path / "config.yaml"; cfg.write_text("fake_pct: 30\n")
    app = create_dashboard(str(cfg), str(tmp_path / "store.db"),
                           "http://ollama:11500", password="s", secret="k")
    with TestClient(app) as c:
        r = c.post("/data/clear", follow_redirects=False)
    assert r.status_code in (302, 303)


def test_clear_route_works_when_logged_in(tmp_path):
    db = str(tmp_path / "store.db")
    jsonl = str(tmp_path / "events.jsonl")
    LoggingStore(db, jsonl).log({"source_ip": "9.9.9.9", "endpoint": "/x", "routed": "real"})
    cfg = tmp_path / "config.yaml"; cfg.write_text("fake_pct: 30\n")
    app = create_dashboard(str(cfg), db, "http://ollama:11500", password="s", secret="k")
    with TestClient(app) as c:
        c.post("/login", data={"password": "s"})
        r = c.post("/data/clear")
    assert r.status_code == 200
    assert "cleared" in r.text.lower()
