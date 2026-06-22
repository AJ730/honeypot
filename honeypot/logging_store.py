from __future__ import annotations

import json
import os
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

    def __init__(
        self,
        db_path: str,
        jsonl_path: str,
        max_jsonl_bytes: int = 100 * 1024 * 1024,
        backup_count: int = 5,
    ):
        self._jsonl_path = jsonl_path
        self._max_jsonl_bytes = max_jsonl_bytes
        self._backup_count = backup_count
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
            # Rotate before appending so the active file is always present after
            # a log() call and never grows unbounded by more than one record.
            self._maybe_rotate_jsonl()
            # Write JSONL first so that a crash before SQLite commit leaves
            # at most a harmless extra JSONL line, never a durable SQLite row
            # missing from JSONL.
            with open(self._jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(row) + "\n")
            self._conn.execute(_INSERT_SQL, [row[k] for k in FIELDS])
            self._conn.commit()

    def _maybe_rotate_jsonl(self) -> None:
        """Size-based rotation of the JSONL file to bound disk over a long run.

        Caller must hold self._lock. When the file exceeds max_jsonl_bytes it is
        rotated to events.jsonl.1, shifting older backups up to backup_count
        (oldest dropped). The SQLite store remains the full queryable record.
        """
        if self._max_jsonl_bytes <= 0:
            return
        try:
            size = os.path.getsize(self._jsonl_path)
        except OSError:
            return
        if size < self._max_jsonl_bytes:
            return
        if self._backup_count <= 0:
            os.remove(self._jsonl_path)
            return
        for i in range(self._backup_count - 1, 0, -1):
            src = "%s.%d" % (self._jsonl_path, i)
            dst = "%s.%d" % (self._jsonl_path, i + 1)
            if os.path.exists(src):
                os.replace(src, dst)
        os.replace(self._jsonl_path, "%s.1" % self._jsonl_path)

    def recent(self, limit: int) -> list[dict]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM requests ORDER BY id DESC LIMIT ?", (limit,)
            )
            return [dict(r) for r in cur.fetchall()]
