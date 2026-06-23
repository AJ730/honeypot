from __future__ import annotations

import os
import sqlite3

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse


def _jsonl_path(db_path: str) -> str:
    return os.environ.get("HONEYPOT_JSONL") or os.path.join(
        os.path.dirname(db_path) or ".", "events.jsonl")


def clear_data(db_path: str, jsonl_path: str) -> None:
    """Wipe all captured request logs from both sinks. Best-effort and safe to
    run while the honeypot is live: it deletes the SQLite rows and truncates the
    JSONL (the honeypot reopens it in append mode on its next write)."""
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("DELETE FROM requests")
            conn.execute("DELETE FROM sqlite_sequence WHERE name='requests'")
            conn.commit()
        except sqlite3.OperationalError:
            pass  # table not created yet
        finally:
            conn.close()
    # Truncate the active JSONL and drop any rotated backups.
    try:
        open(jsonl_path, "w").close()
    except OSError:
        pass
    for i in range(1, 7):
        bak = "%s.%d" % (jsonl_path, i)
        try:
            if os.path.exists(bak):
                os.remove(bak)
        except OSError:
            pass


def register_data_routes(app) -> None:
    router = APIRouter()

    @router.post("/data/clear", response_class=HTMLResponse)
    async def clear(request: Request):
        if not app.state.logged_in(request):
            return RedirectResponse("/login", status_code=303)
        clear_data(app.state.db_path, _jsonl_path(app.state.db_path))
        return HTMLResponse('<div class="notice ok">All logged data cleared. '
                            'New requests will start from a clean slate.</div>')

    app.include_router(router)
