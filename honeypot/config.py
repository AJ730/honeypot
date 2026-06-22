from __future__ import annotations

import os
from dataclasses import dataclass

import yaml


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
    """Loads Config from a YAML file, reloading when the file's mtime changes."""

    def __init__(self, path: str):
        self._path = path
        self._mtime: float | None = None
        self._cfg: Config | None = None

    def get(self) -> Config:
        mtime = os.path.getmtime(self._path)
        if self._cfg is None or mtime != self._mtime:
            with open(self._path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            self._cfg = Config(**raw)
            self._mtime = mtime
        return self._cfg
