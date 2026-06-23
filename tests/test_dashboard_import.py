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


# ---------------------------------------------------------------------------
# _resolve_secret unit tests
# ---------------------------------------------------------------------------

from honeypot.dashboard.main import _resolve_secret  # noqa: E402


def test_resolve_secret_returns_value_for_strong_secret():
    """A strong non-weak secret is returned unchanged."""
    strong = "my-super-secret-token-xyz"
    assert _resolve_secret(strong) == strong


def test_resolve_secret_generates_random_for_empty():
    """An empty secret triggers generation of a new random value."""
    result = _resolve_secret("")
    assert result != ""
    assert len(result) >= 32


def test_resolve_secret_generates_random_for_please_change_me():
    """The 'please-change-me' placeholder triggers generation."""
    result = _resolve_secret("please-change-me")
    assert result != "please-change-me"
    assert len(result) >= 32


def test_resolve_secret_generates_random_for_change_me_dev_secret():
    """The 'change-me-dev-secret' placeholder triggers generation."""
    result = _resolve_secret("change-me-dev-secret")
    assert result != "change-me-dev-secret"
    assert len(result) >= 32


def test_resolve_secret_returns_different_values_each_call():
    """Each call with a weak secret generates a distinct random secret."""
    r1 = _resolve_secret("")
    r2 = _resolve_secret("")
    assert r1 != r2
