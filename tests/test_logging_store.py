import json
from honeypot.logging_store import LoggingStore


def make_store(tmp_path):
    return LoggingStore(str(tmp_path / "store.db"), str(tmp_path / "events.jsonl"))


def sample_record():
    return {
        "ts": "2026-06-22T10:00:00Z",
        "source_ip": "1.2.3.4",
        "dest_ip": "10.20.0.64",
        "method": "POST",
        "endpoint": "/api/generate",
        "model": "qwen2.5:7b",
        "request_body": "{\"prompt\": \"hi\"}",
        "routed": "real",
        "guardrail_trip": None,
        "response_status": 200,
        "latency_ms": 42,
        "version_served": None,
    }


def test_log_writes_sqlite_row(tmp_path):
    store = make_store(tmp_path)
    store.log(sample_record())
    rows = store.recent(10)
    assert len(rows) == 1
    assert rows[0]["source_ip"] == "1.2.3.4"
    assert rows[0]["routed"] == "real"


def test_log_appends_jsonl(tmp_path):
    store = make_store(tmp_path)
    store.log(sample_record())
    store.log(sample_record())
    lines = (tmp_path / "events.jsonl").read_text().strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["endpoint"] == "/api/generate"


def test_log_tolerates_missing_keys(tmp_path):
    store = make_store(tmp_path)
    store.log({"source_ip": "9.9.9.9", "endpoint": "/api/version", "routed": "fake"})
    rows = store.recent(10)
    assert rows[0]["model"] is None
    assert rows[0]["routed"] == "fake"


def test_recent_returns_newest_first(tmp_path):
    store = make_store(tmp_path)
    r1 = sample_record(); r1["source_ip"] = "1.1.1.1"
    r2 = sample_record(); r2["source_ip"] = "2.2.2.2"
    store.log(r1)
    store.log(r2)
    rows = store.recent(10)
    assert rows[0]["source_ip"] == "2.2.2.2"
