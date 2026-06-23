from __future__ import annotations

import asyncio
import json
import sqlite3
from typing import Any

from fastapi import Request
from fastapi.responses import RedirectResponse, StreamingResponse


def fetch_since(db_path: str, last_id: int, limit: int = 100) -> list[dict]:
    """Return request rows with id > last_id, ascending, from the SQLite store.

    Opens the database read-only. Returns [] if the DB file or table is missing.
    """
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
        conn.row_factory = sqlite3.Row
    except Exception:
        return []

    try:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "requests" not in tables:
            return []

        cur = conn.execute(
            "SELECT * FROM requests WHERE id > ? ORDER BY id ASC LIMIT ?",
            (last_id, limit),
        )
        return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []
    finally:
        conn.close()


def _current_max_id(db_path: str) -> int:
    """Return the current maximum id in the requests table, or 0 if unavailable."""
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
        try:
            row = conn.execute("SELECT MAX(id) FROM requests").fetchone()
            return row[0] if (row and row[0] is not None) else 0
        except Exception:
            return 0
        finally:
            conn.close()
    except Exception:
        return 0


def register_feed_routes(app: Any) -> None:
    """Register the /feed SSE route on the given FastAPI app."""

    @app.get("/feed")
    async def feed(request: Request):
        if not app.state.logged_in(request):
            return RedirectResponse("/login", status_code=303)

        db_path = app.state.db_path

        async def gen():
            max_id = _current_max_id(db_path)
            while True:
                rows = fetch_since(db_path, max_id)
                for row in rows:
                    yield ("data: " + json.dumps(row) + "\n\n").encode()
                    max_id = row["id"]
                await asyncio.sleep(1)

        return StreamingResponse(
            gen(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )
