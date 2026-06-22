import json
import os
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


def test_jsonl_rotates_when_size_exceeded(tmp_path):
    db = str(tmp_path / "store.db")
    jsonl = str(tmp_path / "events.jsonl")
    store = LoggingStore(db, jsonl, max_jsonl_bytes=300, backup_count=3)
    for _ in range(40):
        store.log(sample_record())
    assert os.path.exists(jsonl + ".1")          # rotation happened
    assert os.path.getsize(jsonl) <= 300 + 1024  # current file reset to small
    cur = store._conn.execute("select count(*) from requests")
    assert cur.fetchone()[0] == 40               # SQLite keeps ALL rows


def test_jsonl_rotation_respects_backup_count(tmp_path):
    db = str(tmp_path / "store.db")
    jsonl = str(tmp_path / "events.jsonl")
    store = LoggingStore(db, jsonl, max_jsonl_bytes=200, backup_count=2)
    for _ in range(120):
        store.log(sample_record())
    assert os.path.exists(jsonl + ".1")
    assert os.path.exists(jsonl + ".2")
    assert not os.path.exists(jsonl + ".3")      # never more than backup_count


def test_no_rotation_when_disabled(tmp_path):
    db = str(tmp_path / "store.db")
    jsonl = str(tmp_path / "events.jsonl")
    store = LoggingStore(db, jsonl, max_jsonl_bytes=0)  # disabled
    for _ in range(50):
        store.log(sample_record())
    assert not os.path.exists(jsonl + ".1")


def test_recent_returns_newest_first(tmp_path):
    store = make_store(tmp_path)
    r1 = sample_record(); r1["source_ip"] = "1.1.1.1"
    r2 = sample_record(); r2["source_ip"] = "2.2.2.2"
    store.log(r1)
    store.log(r2)
    rows = store.recent(10)
    assert rows[0]["source_ip"] == "2.2.2.2"
