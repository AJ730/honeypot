"""Smoke test: honeypot.dashboard.main.app is non-None iff DASHBOARD_PASSWORD is set."""
import importlib
import sys


def _reload_dashboard(monkeypatch, password: str):
    """Set/unset DASHBOARD_PASSWORD, reload the module, return the module."""
    if password:
        monkeypatch.setenv("DASHBOARD_PASSWORD", password)
    else:
        monkeypatch.delenv("DASHBOARD_PASSWORD", raising=False)
    # Force a fresh import regardless of previous import state.
    sys.modules.pop("honeypot.dashboard.main", None)
    mod = importlib.import_module("honeypot.dashboard.main")
    return mod


def test_app_is_not_none_when_password_set(monkeypatch):
    mod = _reload_dashboard(monkeypatch, "secret123")
    assert mod.app is not None, "app should be a FastAPI instance when DASHBOARD_PASSWORD is set"


def test_app_is_none_when_password_unset(monkeypatch):
    mod = _reload_dashboard(monkeypatch, "")
    assert mod.app is None, "app should be None when DASHBOARD_PASSWORD is empty/unset"
