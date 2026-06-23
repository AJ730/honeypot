from __future__ import annotations

import os
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

try:
    import psutil
except Exception:  # psutil missing — endpoint degrades gracefully
    psutil = None

# Where to read disk usage from. In the container we mount the host root
# read-only at /host so we report the VM's real disk, not the container overlay.
_DISK_PATH = os.environ.get("DASHBOARD_DISK_PATH", "/host")


def _disk_target() -> str:
    return _DISK_PATH if os.path.isdir(_DISK_PATH) else "/"


def compute_system() -> dict:
    """Host resource snapshot. Every field degrades to None on failure so the
    endpoint never raises (a 500 here would just blank the panel)."""
    out: dict = {"available": psutil is not None, "ts": int(time.time())}
    if psutil is None:
        return out

    def safe(fn, default=None):
        try:
            return fn()
        except Exception:
            return default

    # CPU — a short sampling interval gives a real instantaneous percentage.
    out["cpu_percent"] = safe(lambda: psutil.cpu_percent(interval=0.15))
    out["cpu_count"] = safe(lambda: psutil.cpu_count(logical=True))
    out["per_cpu"] = safe(lambda: psutil.cpu_percent(interval=0.0, percpu=True), [])
    load = safe(lambda: psutil.getloadavg())
    out["load_avg"] = list(load) if load else None

    vm = safe(lambda: psutil.virtual_memory())
    if vm:
        out["mem"] = {
            "total": vm.total, "used": vm.used, "available": vm.available,
            "free": vm.free, "percent": vm.percent,
        }
    sw = safe(lambda: psutil.swap_memory())
    if sw:
        out["swap"] = {"total": sw.total, "used": sw.used, "percent": sw.percent}

    du = safe(lambda: psutil.disk_usage(_disk_target()))
    if du:
        out["disk"] = {
            "total": du.total, "used": du.used, "free": du.free, "percent": du.percent,
        }

    boot = safe(lambda: psutil.boot_time())
    if boot:
        out["uptime_seconds"] = int(time.time() - boot)
    return out


def register_system_routes(app) -> None:
    router = APIRouter()

    @router.get("/system")
    async def system(request: Request):
        if not app.state.logged_in(request):
            return RedirectResponse("/login", status_code=303)
        return JSONResponse(compute_system())

    app.include_router(router)
