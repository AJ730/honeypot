from __future__ import annotations

import json
import sqlite3
import threading

FIELDS = [
    "ts", "source_ip", "dest_ip", "method", "endpoint", "model",
    "request_body", "routed", "guardrail_trip", "response_status",
    "latency_ms", "version_served",
]

# Static INSERT SQL built once at module load; values are bound via ? placeholders.
_INSERT_SQL = "INSERT INTO requests ({cols}) VALUES ({placeholders})".format(
    cols=", ".join(FIELDS),
    placeholders=", ".join("?" for _ in FIELDS),
)


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
            # Write JSONL first so that a crash before SQLite commit leaves
            # at most a harmless extra JSONL line, never a durable SQLite row
            # missing from JSONL.
            with open(self._jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(row) + "\n")
            self._conn.execute(_INSERT_SQL, [row[k] for k in FIELDS])
            self._conn.commit()

    def recent(self, limit: int) -> list[dict]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM requests ORDER BY id DESC LIMIT ?", (limit,)
            )
            return [dict(r) for r in cur.fetchall()]
