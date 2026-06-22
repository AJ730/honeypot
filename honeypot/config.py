from __future__ import annotations

import logging
import os
from dataclasses import dataclass

import yaml

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Config:
    fake_pct: int
    real_ollama_url: str
    default_model: str
    advertised_models: list[str]
    versions: list[str]
    guardrail_patterns: list[str]
    fake_responses: list[str]
    max_body_bytes: int


class ConfigStore:
    """Loads Config from a YAML file, reloading when the file's mtime changes.

    If a reload fails (malformed YAML, missing/extra keys — e.g. a bad live edit
    from the dashboard), the last-good config keeps being served instead of
    raising, so a single bad write can never take the public honeypot down. The
    fix is picked up automatically once the file becomes valid again. Only the
    very first load has no fallback and will raise.
    """

    def __init__(self, path: str):
        self._path = path
        self._mtime: float | None = None
        self._failed_mtime: float | None = None
        self._cfg: Config | None = None

    def get(self) -> Config:
        mtime = os.path.getmtime(self._path)
        # Unchanged since the last successful load.
        if self._cfg is not None and mtime == self._mtime:
            return self._cfg
        # Same bad file we already rejected — keep serving last-good, no re-read.
        if mtime == self._failed_mtime and self._cfg is not None:
            return self._cfg
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            if not isinstance(raw, dict):
                raise ValueError(
                    "config root must be a mapping, got %s" % type(raw).__name__
                )
            cfg = Config(**raw)
        except Exception as exc:
            self._failed_mtime = mtime
            if self._cfg is not None:
                _log.warning(
                    "config reload from %s failed (%s); keeping last-good config",
                    self._path, exc,
                )
                return self._cfg
            raise
        self._cfg = cfg
        self._mtime = mtime
        self._failed_mtime = None
        return cfg
