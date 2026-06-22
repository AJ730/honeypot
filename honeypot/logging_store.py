from __future__ import annotations

import json
import sqlite3
import threading

FIELDS = [
    "ts", "source_ip", "dest_ip", "method", "endpoint", "model",
    "request_body", "routed", "guardrail_trip", "response_status",
    "latency_ms", "version_served",
]


class LoggingStore:
    """Dual-writes each request to SQLite (queryable) and JSONL (append-only)."""

    def __init__(self, db_path: str, jsonl_path: str):
        self._jsonl_path = jsonl_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT, source_ip TEXT, dest_ip TEXT, method TEXT,
                endpoint TEXT, model TEXT, request_body TEXT, routed TEXT,
                guardrail_trip TEXT, response_status INTEGER,
                latency_ms INTEGER, version_served TEXT
            )
            """
        )
        self._conn.commit()

    def log(self, record: dict) -> None:
        row = {k: record.get(k) for k in FIELDS}
        with self._lock:
            self._conn.execute(
                "INSERT INTO requests (%s) VALUES (%s)"
                % (", ".join(FIELDS), ", ".join("?" for _ in FIELDS)),
                [row[k] for k in FIELDS],
            )
            self._conn.commit()
            with open(self._jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(row) + "\n")

    def recent(self, limit: int) -> list[dict]:
        cur = self._conn.execute(
            "SELECT * FROM requests ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]
