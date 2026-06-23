from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse


def _zeroed() -> dict:
    """Return a zeroed stats dict for when the DB is missing or empty."""
    return {
        "total_requests": 0,
        "by_endpoint": [],
        "by_routed": {"real": 0, "fake": 0, "blocked": 0},
        "top_source_ips": [],
        "model_preference": [],
        "guardrail_trips": [],
        "version_distribution": [],
        "requests_over_time": [],
    }


def compute_stats(db_path: str) -> dict:
    """Open the honeypot SQLite store read-only and return JSON-serializable aggregates."""
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
        conn.row_factory = sqlite3.Row
    except Exception:
        return _zeroed()

    try:
        # Verify the table exists
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "requests" not in tables:
            return _zeroed()

        result: dict[str, Any] = {}

        # total_requests
        result["total_requests"] = conn.execute(
            "SELECT COUNT(*) FROM requests"
        ).fetchone()[0]

        # by_endpoint
        rows = conn.execute(
            "SELECT endpoint, COUNT(*) AS count FROM requests "
            "WHERE endpoint IS NOT NULL GROUP BY endpoint ORDER BY count DESC"
        ).fetchall()
        result["by_endpoint"] = [{"endpoint": r["endpoint"], "count": r["count"]} for r in rows]

        # by_routed — ensure real/fake/blocked keys always present, defaulting to 0
        routed_rows = conn.execute(
            "SELECT routed, COUNT(*) AS count FROM requests "
            "WHERE routed IS NOT NULL GROUP BY routed"
        ).fetchall()
        by_routed = {"real": 0, "fake": 0, "blocked": 0}
        for r in routed_rows:
            key = r["routed"]
            by_routed[key] = r["count"]
        result["by_routed"] = by_routed

        # top_source_ips (top 10)
        rows = conn.execute(
            "SELECT source_ip, COUNT(*) AS count FROM requests "
            "WHERE source_ip IS NOT NULL GROUP BY source_ip "
            "ORDER BY count DESC LIMIT 10"
        ).fetchall()
        result["top_source_ips"] = [{"source_ip": r["source_ip"], "count": r["count"]} for r in rows]

        # model_preference
        rows = conn.execute(
            "SELECT model, COUNT(*) AS count FROM requests "
            "WHERE model IS NOT NULL GROUP BY model ORDER BY count DESC"
        ).fetchall()
        result["model_preference"] = [{"model": r["model"], "count": r["count"]} for r in rows]

        # guardrail_trips (keyed by reason)
        rows = conn.execute(
            "SELECT guardrail_trip AS reason, COUNT(*) AS count FROM requests "
            "WHERE guardrail_trip IS NOT NULL GROUP BY guardrail_trip ORDER BY count DESC"
        ).fetchall()
        result["guardrail_trips"] = [{"reason": r["reason"], "count": r["count"]} for r in rows]

        # version_distribution
        rows = conn.execute(
            "SELECT version_served, COUNT(*) AS count FROM requests "
            "WHERE version_served IS NOT NULL GROUP BY version_served ORDER BY count DESC"
        ).fetchall()
        result["version_distribution"] = [
            {"version_served": r["version_served"], "count": r["count"]} for r in rows
        ]

        # requests_over_time (bucketed by hour)
        # ts is stored as ISO-8601 text; strftime('%Y-%m-%dT%H', ts) extracts hour bucket
        rows = conn.execute(
            "SELECT strftime('%Y-%m-%dT%H', ts) AS bucket, COUNT(*) AS count "
            "FROM requests WHERE ts IS NOT NULL GROUP BY bucket ORDER BY bucket"
        ).fetchall()
        result["requests_over_time"] = [{"bucket": r["bucket"], "count": r["count"]} for r in rows]

        return result

    except Exception:
        return _zeroed()
    finally:
        conn.close()


def register_stats_routes(app: Any) -> None:
    """Register the /stats JSON route on the given FastAPI app."""

    @app.get("/stats")
    async def stats(request: Request):
        if not app.state.logged_in(request):
            return RedirectResponse("/login", status_code=303)
        return JSONResponse(compute_stats(app.state.db_path))
