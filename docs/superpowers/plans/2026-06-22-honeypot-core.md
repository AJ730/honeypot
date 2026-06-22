# Honeypot Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deceptive, Ollama-compatible reverse-proxy service on `:11434` that serves a mix of real and mocked responses, logs every request, and enforces ethical guardrails.

**Architecture:** A single FastAPI app is the only public listener on `:11434`. It proxies select endpoints to a private real Ollama (`127.0.0.1:11500`), serves mocked responses for others, applies a deterministic ~30% fake-vs-real split on `/api/generate` and `/api/chat`, screens prompts through guardrails, and dual-logs every request to SQLite + JSONL. All behavior is driven by a hot-reloadable `config.yaml`.

**Tech Stack:** Python 3.11+, FastAPI, Starlette, httpx (async), PyYAML, SQLite (stdlib `sqlite3`), pytest, pytest-asyncio.

## Global Constraints

- Public listener `:11434` runs **only** the honeypot — no other surface.
- Real Ollama is reached at `config.real_ollama_url` (default `http://127.0.0.1:11500`) and is never exposed publicly.
- Mocked responses must match real Ollama's wire format (a scanner must not be able to tell real from fake on the wire), including NDJSON streaming shape for generate/chat.
- Fake-vs-real and version decisions must be **deterministic** per source IP so a given scanner sees stable behavior on repeat contact.
- Every request is logged exactly once with `routed` ∈ {`real`, `fake`, `blocked`}.
- `request_body` is capped at `config.max_body_bytes` (default 65536) before storage.
- Guardrail trips never call the real model and return an in-character Ollama-formatted refusal (HTTP 200), not an error.
- All config values come from `config.yaml`; no hardcoded thresholds in logic modules.

---

### Task 1: Project scaffold, dependencies, and config module

**Files:**
- Create: `requirements.txt`
- Create: `honeypot/__init__.py`
- Create: `honeypot/config.py`
- Create: `config.yaml`
- Create: `tests/__init__.py`
- Create: `tests/test_config.py`

**Interfaces:**
- Consumes: nothing (first task).
- Produces:
  - `honeypot.config.Config` — dataclass with fields: `fake_pct: int`, `real_ollama_url: str`, `default_model: str`, `advertised_models: list[str]`, `versions: list[str]`, `guardrail_patterns: list[str]`, `fake_responses: list[str]`, `max_body_bytes: int`.
  - `honeypot.config.ConfigStore(path: str)` with `.get() -> Config` that reloads from disk when the file's mtime changes.

- [ ] **Step 1: Create `requirements.txt`**

```
fastapi==0.115.6
uvicorn[standard]==0.34.0
httpx==0.28.1
PyYAML==6.0.2
pytest==8.3.4
pytest-asyncio==0.25.0
```

- [ ] **Step 2: Create `config.yaml`**

```yaml
fake_pct: 30
real_ollama_url: "http://127.0.0.1:11500"
default_model: "qwen2.5:7b"
advertised_models:
  - "qwen2.5:7b"
  - "qwen2.5:3b"
versions:
  - "0.1.20"
  - "0.3.6"
  - "0.5.7"
  - "0.9.0"
  - "0.11.4"
  - "0.12.6"
guardrail_patterns:
  - "phishing"
  - "write malware"
  - "ransomware"
  - "steal credentials"
  - "credit card dump"
  - "exploit kit"
fake_responses:
  - "I'm a large language model and I'm happy to help. Could you give me a bit more detail about what you're looking for?"
  - "Sure — here's a high-level overview. Let me know if you'd like me to go deeper on any part."
max_body_bytes: 65536
```

- [ ] **Step 3: Create empty `honeypot/__init__.py` and `tests/__init__.py`**

Both files are empty.

- [ ] **Step 4: Write the failing test for `tests/test_config.py`**

```python
import time
from honeypot.config import Config, ConfigStore


def write_yaml(path, fake_pct=30):
    path.write_text(
        "fake_pct: %d\n"
        "real_ollama_url: \"http://127.0.0.1:11500\"\n"
        "default_model: \"qwen2.5:7b\"\n"
        "advertised_models: [\"qwen2.5:7b\"]\n"
        "versions: [\"0.12.6\"]\n"
        "guardrail_patterns: [\"phishing\"]\n"
        "fake_responses: [\"hi\"]\n"
        "max_body_bytes: 65536\n" % fake_pct
    )


def test_loads_config(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    write_yaml(cfg_path)
    store = ConfigStore(str(cfg_path))
    cfg = store.get()
    assert isinstance(cfg, Config)
    assert cfg.fake_pct == 30
    assert cfg.default_model == "qwen2.5:7b"
    assert cfg.advertised_models == ["qwen2.5:7b"]


def test_hot_reload_on_mtime_change(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    write_yaml(cfg_path, fake_pct=30)
    store = ConfigStore(str(cfg_path))
    assert store.get().fake_pct == 30
    time.sleep(0.01)
    write_yaml(cfg_path, fake_pct=50)
    # bump mtime explicitly to be filesystem-independent
    import os
    os.utime(cfg_path, (time.time() + 1, time.time() + 1))
    assert store.get().fake_pct == 50
```

- [ ] **Step 5: Run test to verify it fails**

Run: `pytest tests/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'honeypot.config'`

- [ ] **Step 6: Write `honeypot/config.py`**

```python
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
```

- [ ] **Step 7: Run test to verify it passes**

Run: `pytest tests/test_config.py -v`
Expected: PASS (2 passed)

- [ ] **Step 8: Commit**

```bash
git add requirements.txt config.yaml honeypot/__init__.py honeypot/config.py tests/__init__.py tests/test_config.py
git commit -m "feat: project scaffold and hot-reloadable config"
```

---

### Task 2: Logging store (SQLite + JSONL)

**Files:**
- Create: `honeypot/logging_store.py`
- Create: `tests/test_logging_store.py`

**Interfaces:**
- Consumes: nothing from prior tasks.
- Produces:
  - `honeypot.logging_store.LoggingStore(db_path: str, jsonl_path: str)`.
  - `LoggingStore.log(record: dict) -> None` — writes one row to SQLite table `requests` and appends one JSON line to the JSONL file. Recognized keys: `ts, source_ip, dest_ip, method, endpoint, model, request_body, routed, guardrail_trip, response_status, latency_ms, version_served`. Missing keys default to `None`.
  - `LoggingStore.recent(limit: int) -> list[dict]` — returns the most recent rows (newest first) as dicts. Used later by the dashboard plan.

- [ ] **Step 1: Write the failing test for `tests/test_logging_store.py`**

```python
import json
from honeypot.logging_store import LoggingStore


def make_store(tmp_path):
    return LoggingStore(str(tmp_path / "store.db"), str(tmp_path / "events.jsonl"))


def sample_record():
    return {
        "ts": "2026-06-22T10:00:00Z",
        "source_ip": "1.2.3.4",
        "dest_ip": "10.20.0.64",
        "method": "POST",
        "endpoint": "/api/generate",
        "model": "qwen2.5:7b",
        "request_body": "{\"prompt\": \"hi\"}",
        "routed": "real",
        "guardrail_trip": None,
        "response_status": 200,
        "latency_ms": 42,
        "version_served": None,
    }


def test_log_writes_sqlite_row(tmp_path):
    store = make_store(tmp_path)
    store.log(sample_record())
    rows = store.recent(10)
    assert len(rows) == 1
    assert rows[0]["source_ip"] == "1.2.3.4"
    assert rows[0]["routed"] == "real"


def test_log_appends_jsonl(tmp_path):
    store = make_store(tmp_path)
    store.log(sample_record())
    store.log(sample_record())
    lines = (tmp_path / "events.jsonl").read_text().strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["endpoint"] == "/api/generate"


def test_log_tolerates_missing_keys(tmp_path):
    store = make_store(tmp_path)
    store.log({"source_ip": "9.9.9.9", "endpoint": "/api/version", "routed": "fake"})
    rows = store.recent(10)
    assert rows[0]["model"] is None
    assert rows[0]["routed"] == "fake"


def test_recent_returns_newest_first(tmp_path):
    store = make_store(tmp_path)
    r1 = sample_record(); r1["source_ip"] = "1.1.1.1"
    r2 = sample_record(); r2["source_ip"] = "2.2.2.2"
    store.log(r1)
    store.log(r2)
    rows = store.recent(10)
    assert rows[0]["source_ip"] == "2.2.2.2"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_logging_store.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'honeypot.logging_store'`

- [ ] **Step 3: Write `honeypot/logging_store.py`**

```python
from __future__ import annotations

import json
import sqlite3
import threading

FIELDS = [
    "ts", "source_ip", "dest_ip", "method", "endpoint", "model",
    "request_body", "routed", "guardrail_trip", "response_status",
    "latency_ms", "version_served",
]


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
            self._conn.execute(
                "INSERT INTO requests (%s) VALUES (%s)"
                % (", ".join(FIELDS), ", ".join("?" for _ in FIELDS)),
                [row[k] for k in FIELDS],
            )
            self._conn.commit()
            with open(self._jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(row) + "\n")

    def recent(self, limit: int) -> list[dict]:
        cur = self._conn.execute(
            "SELECT * FROM requests ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_logging_store.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add honeypot/logging_store.py tests/test_logging_store.py
git commit -m "feat: dual-write SQLite + JSONL logging store"
```

---

### Task 3: Mocked-endpoint responses (`fakes.py`)

**Files:**
- Create: `honeypot/fakes.py`
- Create: `tests/test_fakes.py`

**Interfaces:**
- Consumes: nothing from prior tasks.
- Produces:
  - `fake_embed(body: dict) -> dict` — Ollama `/api/embed` shape with randomized values; embedding length scales with input token count.
  - `fake_version(source_ip: str, versions: list[str]) -> str` — deterministic per source IP.
  - Static constants/helpers: `CREATE_RESPONSE = {"status": "success"}`, `PULL_RESPONSE = {"status": "success"}`, `PUSH_RESPONSE = {"status": "success"}`, `COPY_OK = "200 OK"`, `DELETE_OK = "Model successfully deleted"`.
  - `fake_completion(body: dict, fake_responses: list[str]) -> dict` — Ollama `/api/generate`-shaped non-streaming response drawing text deterministically from `fake_responses` by prompt hash.

- [ ] **Step 1: Write the failing test for `tests/test_fakes.py`**

```python
from honeypot.fakes import (
    fake_embed, fake_version, fake_completion,
    CREATE_RESPONSE, PULL_RESPONSE, PUSH_RESPONSE, COPY_OK, DELETE_OK,
)


def test_fake_embed_shape_and_echo_model():
    body = {"model": "embeddinggemma", "input": "Why is the sky blue?"}
    out = fake_embed(body)
    assert out["model"] == "embeddinggemma"
    assert isinstance(out["embeddings"], list)
    assert isinstance(out["embeddings"][0], list)
    assert all(isinstance(x, float) for x in out["embeddings"][0])
    assert out["prompt_eval_count"] >= 1
    assert out["total_duration"] > 0
    assert out["load_duration"] > 0


def test_fake_embed_scales_with_input():
    short = fake_embed({"model": "m", "input": "hi"})
    long = fake_embed({"model": "m", "input": "word " * 200})
    assert long["prompt_eval_count"] > short["prompt_eval_count"]


def test_fake_version_deterministic_per_ip():
    versions = ["0.1.20", "0.5.7", "0.12.6"]
    a = fake_version("1.2.3.4", versions)
    b = fake_version("1.2.3.4", versions)
    assert a == b
    assert a in versions


def test_fake_version_varies_across_ips():
    versions = ["0.1.20", "0.3.6", "0.5.7", "0.9.0", "0.11.4", "0.12.6"]
    seen = {fake_version(f"10.0.0.{i}", versions) for i in range(50)}
    assert len(seen) > 1


def test_static_responses():
    assert CREATE_RESPONSE == {"status": "success"}
    assert PULL_RESPONSE == {"status": "success"}
    assert PUSH_RESPONSE == {"status": "success"}
    assert COPY_OK == "200 OK"
    assert DELETE_OK == "Model successfully deleted"


def test_fake_completion_shape_and_determinism():
    body = {"model": "qwen2.5:7b", "prompt": "explain TLS"}
    a = fake_completion(body, ["resp-a", "resp-b"])
    b = fake_completion(body, ["resp-a", "resp-b"])
    assert a["response"] == b["response"]
    assert a["model"] == "qwen2.5:7b"
    assert a["done"] is True
    assert a["response"] in ("resp-a", "resp-b")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_fakes.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'honeypot.fakes'`

- [ ] **Step 3: Write `honeypot/fakes.py`**

```python
from __future__ import annotations

import hashlib

CREATE_RESPONSE = {"status": "success"}
PULL_RESPONSE = {"status": "success"}
PUSH_RESPONSE = {"status": "success"}
COPY_OK = "200 OK"
DELETE_OK = "Model successfully deleted"


def _seeded_floats(seed: str, n: int) -> list[float]:
    """Deterministic-but-varied pseudo-random floats in [-1, 1) from a seed."""
    out = []
    i = 0
    while len(out) < n:
        h = hashlib.sha256(f"{seed}:{i}".encode()).digest()
        for j in range(0, len(h), 4):
            val = int.from_bytes(h[j:j + 4], "big") / 0xFFFFFFFF
            out.append(val * 2 - 1)
            if len(out) >= n:
                break
        i += 1
    return out


def _token_count(text: str) -> int:
    return max(1, len(text.split()))


def fake_embed(body: dict) -> dict:
    model = body.get("model", "embeddinggemma")
    text = str(body.get("input", ""))
    tokens = _token_count(text)
    dims = min(10 + tokens, 768)
    floats = _seeded_floats(f"embed:{text}", dims)
    durations = _seeded_floats(f"dur:{text}", 2)
    return {
        "model": model,
        "embeddings": [floats],
        "total_duration": int(10_000_000 + abs(durations[0]) * 10_000_000),
        "load_duration": int(500_000 + abs(durations[1]) * 1_000_000),
        "prompt_eval_count": tokens,
    }


def fake_version(source_ip: str, versions: list[str]) -> str:
    h = int(hashlib.sha256(source_ip.encode()).hexdigest(), 16)
    return versions[h % len(versions)]


def fake_completion(body: dict, fake_responses: list[str]) -> dict:
    model = body.get("model", "qwen2.5:7b")
    prompt = str(body.get("prompt") or body.get("messages") or "")
    h = int(hashlib.sha256(prompt.encode()).hexdigest(), 16)
    text = fake_responses[h % len(fake_responses)] if fake_responses else ""
    return {
        "model": model,
        "created_at": "2026-06-22T10:00:00.000000Z",
        "response": text,
        "done": True,
        "done_reason": "stop",
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_fakes.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add honeypot/fakes.py tests/test_fakes.py
git commit -m "feat: mocked endpoint responses (embed, version, static, completion)"
```

---

### Task 4: Fake-vs-real router

**Files:**
- Create: `honeypot/router.py`
- Create: `tests/test_router.py`

**Interfaces:**
- Consumes: nothing from prior tasks.
- Produces:
  - `should_fake(source_ip: str, prompt: str, fake_pct: int) -> bool` — deterministic via `hash(source_ip + prompt) % 100 < fake_pct`. `fake_pct <= 0` → always False; `fake_pct >= 100` → always True.
  - `extract_prompt(body: dict) -> str` — pulls the user text from a `/api/generate` (`prompt`) or `/api/chat` (`messages[].content`) body.

- [ ] **Step 1: Write the failing test for `tests/test_router.py`**

```python
from honeypot.router import should_fake, extract_prompt


def test_deterministic_same_input():
    a = should_fake("1.2.3.4", "hello", 30)
    b = should_fake("1.2.3.4", "hello", 30)
    assert a == b


def test_zero_pct_never_fakes():
    assert should_fake("1.2.3.4", "x", 0) is False


def test_full_pct_always_fakes():
    assert should_fake("1.2.3.4", "x", 100) is True


def test_distribution_approximately_pct():
    n = 5000
    fakes = sum(should_fake(f"10.0.{i // 256}.{i % 256}", "probe", 30) for i in range(n))
    ratio = fakes / n
    assert 0.25 < ratio < 0.35


def test_extract_prompt_generate():
    assert extract_prompt({"prompt": "why blue?"}) == "why blue?"


def test_extract_prompt_chat():
    body = {"messages": [{"role": "user", "content": "hi there"}]}
    assert extract_prompt(body) == "hi there"


def test_extract_prompt_chat_multiple_uses_last_user():
    body = {"messages": [
        {"role": "user", "content": "first"},
        {"role": "assistant", "content": "ok"},
        {"role": "user", "content": "second"},
    ]}
    assert extract_prompt(body) == "second"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_router.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'honeypot.router'`

- [ ] **Step 3: Write `honeypot/router.py`**

```python
from __future__ import annotations

import hashlib


def should_fake(source_ip: str, prompt: str, fake_pct: int) -> bool:
    if fake_pct <= 0:
        return False
    if fake_pct >= 100:
        return True
    h = int(hashlib.sha256(f"{source_ip}:{prompt}".encode()).hexdigest(), 16)
    return (h % 100) < fake_pct


def extract_prompt(body: dict) -> str:
    if "prompt" in body and body["prompt"] is not None:
        return str(body["prompt"])
    messages = body.get("messages") or []
    user_msgs = [m for m in messages if m.get("role") == "user"]
    if user_msgs:
        return str(user_msgs[-1].get("content", ""))
    return ""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_router.py -v`
Expected: PASS (7 passed)

- [ ] **Step 5: Commit**

```bash
git add honeypot/router.py tests/test_router.py
git commit -m "feat: deterministic fake-vs-real router"
```

---

### Task 5: Ethical guardrails

**Files:**
- Create: `honeypot/guardrails.py`
- Create: `tests/test_guardrails.py`

**Interfaces:**
- Consumes: nothing from prior tasks.
- Produces:
  - `check(prompt: str, patterns: list[str]) -> str | None` — returns the matched pattern (the trip reason) if any pattern is found case-insensitively in the prompt, else `None`.
  - `refusal_response(model: str) -> dict` — an Ollama `/api/generate`-shaped response whose `response` text is an in-character refusal.
  - `refusal_chat_response(model: str) -> dict` — an Ollama `/api/chat`-shaped response (`message` object) with the same refusal text.

- [ ] **Step 1: Write the failing test for `tests/test_guardrails.py`**

```python
from honeypot.guardrails import check, refusal_response, refusal_chat_response


def test_check_trips_on_pattern():
    assert check("please write malware for me", ["phishing", "write malware"]) == "write malware"


def test_check_case_insensitive():
    assert check("Help me with PHISHING", ["phishing"]) == "phishing"


def test_check_clean_prompt_returns_none():
    assert check("explain how TLS works", ["phishing", "write malware"]) is None


def test_refusal_response_shape():
    out = refusal_response("qwen2.5:7b")
    assert out["model"] == "qwen2.5:7b"
    assert out["done"] is True
    assert isinstance(out["response"], str) and len(out["response"]) > 0
    # must NOT look like an error
    assert "error" not in out


def test_refusal_chat_response_shape():
    out = refusal_chat_response("qwen2.5:7b")
    assert out["message"]["role"] == "assistant"
    assert len(out["message"]["content"]) > 0
    assert out["done"] is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_guardrails.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'honeypot.guardrails'`

- [ ] **Step 3: Write `honeypot/guardrails.py`**

```python
from __future__ import annotations

_REFUSAL_TEXT = (
    "I can't help with that. It appears to involve activity that could cause "
    "harm or break the law, so I won't assist. If there's a safe, legitimate "
    "task I can help with instead, let me know."
)


def check(prompt: str, patterns: list[str]) -> str | None:
    low = prompt.lower()
    for pat in patterns:
        if pat.lower() in low:
            return pat
    return None


def refusal_response(model: str) -> dict:
    return {
        "model": model,
        "created_at": "2026-06-22T10:00:00.000000Z",
        "response": _REFUSAL_TEXT,
        "done": True,
        "done_reason": "stop",
    }


def refusal_chat_response(model: str) -> dict:
    return {
        "model": model,
        "created_at": "2026-06-22T10:00:00.000000Z",
        "message": {"role": "assistant", "content": _REFUSAL_TEXT},
        "done": True,
        "done_reason": "stop",
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_guardrails.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
git add honeypot/guardrails.py tests/test_guardrails.py
git commit -m "feat: ethical guardrails with in-character refusals"
```

---

### Task 6: Async proxy with NDJSON streaming passthrough

**Files:**
- Create: `honeypot/proxy.py`
- Create: `tests/test_proxy.py`

**Interfaces:**
- Consumes: nothing from prior tasks.
- Produces:
  - `async forward_json(client: httpx.AsyncClient, base_url: str, path: str, method: str, body: bytes | None) -> tuple[int, dict]` — forwards a non-streaming request, returns `(status_code, json_dict)`.
  - `async stream_generate(client: httpx.AsyncClient, base_url: str, path: str, body: bytes) -> AsyncIterator[bytes]` — forwards a POST and yields the upstream NDJSON byte chunks verbatim for streaming passthrough.

- [ ] **Step 1: Write the failing test for `tests/test_proxy.py`**

```python
import json
import httpx
import pytest
from honeypot.proxy import forward_json, stream_generate


def make_client(handler):
    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=transport)


@pytest.mark.asyncio
async def test_forward_json_returns_status_and_body():
    def handler(request):
        assert request.url.path == "/api/tags"
        return httpx.Response(200, json={"models": [{"name": "qwen2.5:7b"}]})

    async with make_client(handler) as client:
        status, body = await forward_json(client, "http://up", "/api/tags", "GET", None)
    assert status == 200
    assert body["models"][0]["name"] == "qwen2.5:7b"


@pytest.mark.asyncio
async def test_forward_json_forwards_post_body():
    seen = {}

    def handler(request):
        seen["body"] = request.content
        return httpx.Response(200, json={"ok": True})

    async with make_client(handler) as client:
        status, body = await forward_json(
            client, "http://up", "/api/show", "POST", b'{"model":"x"}'
        )
    assert status == 200
    assert seen["body"] == b'{"model":"x"}'


@pytest.mark.asyncio
async def test_stream_generate_yields_ndjson_chunks_verbatim():
    chunks = [
        json.dumps({"response": "hel", "done": False}).encode() + b"\n",
        json.dumps({"response": "lo", "done": True}).encode() + b"\n",
    ]

    def handler(request):
        return httpx.Response(200, content=b"".join(chunks))

    async with make_client(handler) as client:
        out = b""
        async for c in stream_generate(client, "http://up", "/api/generate", b"{}"):
            out += c
    assert out == b"".join(chunks)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_proxy.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'honeypot.proxy'`

- [ ] **Step 3: Write `honeypot/proxy.py`**

```python
from __future__ import annotations

from typing import AsyncIterator

import httpx


async def forward_json(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    method: str,
    body: bytes | None,
) -> tuple[int, dict]:
    resp = await client.request(
        method, base_url + path, content=body,
        headers={"content-type": "application/json"} if body else None,
    )
    try:
        data = resp.json()
    except Exception:
        data = {}
    return resp.status_code, data


async def stream_generate(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    body: bytes,
) -> AsyncIterator[bytes]:
    async with client.stream(
        "POST", base_url + path, content=body,
        headers={"content-type": "application/json"},
    ) as resp:
        async for chunk in resp.aiter_raw():
            yield chunk
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_proxy.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add honeypot/proxy.py tests/test_proxy.py
git commit -m "feat: async proxy with NDJSON streaming passthrough"
```

---

### Task 7: FastAPI app wiring all endpoints

**Files:**
- Create: `honeypot/main.py`
- Create: `tests/test_endpoints.py`

**Interfaces:**
- Consumes:
  - `honeypot.config.ConfigStore`, `Config`
  - `honeypot.logging_store.LoggingStore`
  - `honeypot.fakes.*` (`fake_embed`, `fake_version`, `fake_completion`, `CREATE_RESPONSE`, `PULL_RESPONSE`, `PUSH_RESPONSE`, `COPY_OK`, `DELETE_OK`)
  - `honeypot.router.should_fake`, `extract_prompt`
  - `honeypot.guardrails.check`, `refusal_response`, `refusal_chat_response`
  - `honeypot.proxy.forward_json`, `stream_generate`
- Produces:
  - `create_app(config_path: str, db_path: str, jsonl_path: str, client: httpx.AsyncClient | None = None) -> FastAPI` — factory wiring all routes. `client` is injectable for tests; if `None`, a real `httpx.AsyncClient` is created on startup.
  - Module-level `app = create_app("config.yaml", "store.db", "events.jsonl")` for uvicorn.

- [ ] **Step 1: Write the failing test for `tests/test_endpoints.py`**

```python
import json
import httpx
import pytest
from starlette.testclient import TestClient
from honeypot.main import create_app


def write_config(tmp_path, fake_pct=0):
    p = tmp_path / "config.yaml"
    p.write_text(
        "fake_pct: %d\n"
        "real_ollama_url: \"http://up\"\n"
        "default_model: \"qwen2.5:7b\"\n"
        "advertised_models: [\"qwen2.5:7b\", \"qwen2.5:3b\"]\n"
        "versions: [\"0.12.6\"]\n"
        "guardrail_patterns: [\"write malware\"]\n"
        "fake_responses: [\"canned reply\"]\n"
        "max_body_bytes: 65536\n" % fake_pct
    )
    return p


def upstream_handler(request):
    if request.url.path == "/api/tags":
        return httpx.Response(200, json={"models": [{"name": "qwen2.5:7b"}]})
    if request.url.path in ("/api/generate", "/api/chat"):
        return httpx.Response(200, content=b'{"response":"real","done":true}\n')
    return httpx.Response(200, json={"ok": True})


def build(tmp_path, fake_pct=0):
    cfg = write_config(tmp_path, fake_pct)
    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    app = create_app(str(cfg), str(tmp_path / "store.db"),
                     str(tmp_path / "events.jsonl"), client=client)
    return app


def test_tags_is_proxied_real(tmp_path):
    with TestClient(build(tmp_path)) as c:
        r = c.get("/api/tags")
    assert r.status_code == 200
    assert r.json()["models"][0]["name"] == "qwen2.5:7b"


def test_version_is_faked_and_deterministic(tmp_path):
    with TestClient(build(tmp_path)) as c:
        r1 = c.get("/api/version")
        r2 = c.get("/api/version")
    assert r1.json()["version"] == "0.12.6"
    assert r1.json() == r2.json()


def test_embed_is_faked(tmp_path):
    with TestClient(build(tmp_path)) as c:
        r = c.post("/api/embed", json={"model": "embeddinggemma", "input": "hi"})
    body = r.json()
    assert body["model"] == "embeddinggemma"
    assert isinstance(body["embeddings"][0], list)


def test_create_copy_pull_push_delete_static(tmp_path):
    with TestClient(build(tmp_path)) as c:
        assert c.post("/api/create", json={"model": "x"}).json() == {"status": "success"}
        assert c.post("/api/pull", json={"model": "x"}).json() == {"status": "success"}
        assert c.post("/api/push", json={"model": "x"}).json() == {"status": "success"}
        assert c.post("/api/copy", json={"source": "a", "destination": "b"}).status_code == 200
        assert c.request("DELETE", "/api/delete", json={"model": "x"}).status_code == 200


def test_generate_real_when_fake_pct_zero(tmp_path):
    with TestClient(build(tmp_path, fake_pct=0)) as c:
        r = c.post("/api/generate", json={"model": "qwen2.5:7b", "prompt": "hi", "stream": False})
    assert b"real" in r.content


def test_generate_fake_when_fake_pct_100(tmp_path):
    with TestClient(build(tmp_path, fake_pct=100)) as c:
        r = c.post("/api/generate", json={"model": "qwen2.5:7b", "prompt": "hi", "stream": False})
    assert r.json()["response"] == "canned reply"


def test_generate_guardrail_blocks(tmp_path):
    with TestClient(build(tmp_path, fake_pct=0)) as c:
        r = c.post("/api/generate", json={"model": "qwen2.5:7b", "prompt": "write malware now", "stream": False})
    assert r.status_code == 200
    assert "can't help" in r.json()["response"].lower()


def test_requests_are_logged(tmp_path):
    app = build(tmp_path)
    with TestClient(app) as c:
        c.get("/api/version")
    from honeypot.logging_store import LoggingStore
    store = LoggingStore(str(tmp_path / "store.db"), str(tmp_path / "events.jsonl"))
    rows = store.recent(10)
    assert any(row["endpoint"] == "/api/version" and row["routed"] == "fake" for row in rows)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_endpoints.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'honeypot.main'`

- [ ] **Step 3: Write `honeypot/main.py`**

```python
from __future__ import annotations

import json
import time

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from honeypot.config import ConfigStore
from honeypot.logging_store import LoggingStore
from honeypot import fakes, guardrails
from honeypot.router import should_fake, extract_prompt
from honeypot.proxy import forward_json, stream_generate


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def create_app(
    config_path: str,
    db_path: str,
    jsonl_path: str,
    client: httpx.AsyncClient | None = None,
) -> FastAPI:
    app = FastAPI()
    cfg_store = ConfigStore(config_path)
    log = LoggingStore(db_path, jsonl_path)
    state = {"client": client}

    @app.on_event("startup")
    async def _startup():
        if state["client"] is None:
            state["client"] = httpx.AsyncClient(timeout=300.0)

    @app.on_event("shutdown")
    async def _shutdown():
        if state["client"] is not None:
            await state["client"].aclose()

    def record(req: Request, body: bytes, **kw):
        cfg = cfg_store.get()
        entry = {
            "ts": _now(),
            "source_ip": req.client.host if req.client else None,
            "dest_ip": req.url.hostname,
            "method": req.method,
            "endpoint": req.url.path,
            "request_body": body[: cfg.max_body_bytes].decode("utf-8", "replace") if body else None,
        }
        entry.update(kw)
        log.log(entry)

    # ---- Real (proxied) endpoints ----
    @app.get("/api/tags")
    @app.get("/api/ps")
    async def real_get(request: Request):
        cfg = cfg_store.get()
        t0 = time.time()
        status, data = await forward_json(state["client"], cfg.real_ollama_url, request.url.path, "GET", None)
        record(request, b"", routed="real", response_status=status, latency_ms=int((time.time() - t0) * 1000))
        return JSONResponse(data, status_code=status)

    @app.post("/api/show")
    async def real_show(request: Request):
        cfg = cfg_store.get()
        body = await request.body()
        t0 = time.time()
        status, data = await forward_json(state["client"], cfg.real_ollama_url, "/api/show", "POST", body)
        record(request, body, routed="real", response_status=status, latency_ms=int((time.time() - t0) * 1000))
        return JSONResponse(data, status_code=status)

    # ---- Faked static/template endpoints ----
    @app.get("/api/version")
    async def version(request: Request):
        cfg = cfg_store.get()
        ip = request.client.host if request.client else "0.0.0.0"
        v = fakes.fake_version(ip, cfg.versions)
        record(request, b"", routed="fake", response_status=200, version_served=v)
        return JSONResponse({"version": v})

    @app.post("/api/embed")
    async def embed(request: Request):
        body = await request.body()
        data = fakes.fake_embed(json.loads(body or b"{}"))
        record(request, body, routed="fake", response_status=200)
        return JSONResponse(data)

    @app.post("/api/create")
    async def create(request: Request):
        body = await request.body()
        record(request, body, routed="fake", response_status=200)
        return JSONResponse(fakes.CREATE_RESPONSE)

    @app.post("/api/pull")
    async def pull(request: Request):
        body = await request.body()
        record(request, body, routed="fake", response_status=200)
        return JSONResponse(fakes.PULL_RESPONSE)

    @app.post("/api/push")
    async def push(request: Request):
        body = await request.body()
        record(request, body, routed="fake", response_status=200)
        return JSONResponse(fakes.PUSH_RESPONSE)

    @app.post("/api/copy")
    async def copy(request: Request):
        body = await request.body()
        record(request, body, routed="fake", response_status=200)
        return Response(status_code=200)

    @app.api_route("/api/delete", methods=["DELETE"])
    async def delete(request: Request):
        body = await request.body()
        record(request, body, routed="fake", response_status=200)
        return Response(content=fakes.DELETE_OK, status_code=200)

    # ---- generate / chat: guardrail -> fake/real ----
    async def _handle_generate(request: Request, is_chat: bool):
        cfg = cfg_store.get()
        body = await request.body()
        parsed = json.loads(body or b"{}")
        model = parsed.get("model", cfg.default_model)
        prompt = extract_prompt(parsed)
        ip = request.client.host if request.client else "0.0.0.0"

        trip = guardrails.check(prompt, cfg.guardrail_patterns)
        if trip is not None:
            data = guardrails.refusal_chat_response(model) if is_chat else guardrails.refusal_response(model)
            record(request, body, model=model, routed="blocked", guardrail_trip=trip, response_status=200)
            return JSONResponse(data)

        if should_fake(ip, prompt, cfg.fake_pct):
            data = fakes.fake_completion(parsed, cfg.fake_responses)
            if is_chat:
                data = {"model": model, "created_at": data["created_at"],
                        "message": {"role": "assistant", "content": data["response"]},
                        "done": True, "done_reason": "stop"}
            record(request, body, model=model, routed="fake", response_status=200)
            return JSONResponse(data)

        t0 = time.time()
        record(request, body, model=model, routed="real", response_status=200,
               latency_ms=int((time.time() - t0) * 1000))
        gen = stream_generate(state["client"], cfg.real_ollama_url, request.url.path, body)
        return StreamingResponse(gen, media_type="application/x-ndjson")

    @app.post("/api/generate")
    async def generate(request: Request):
        return await _handle_generate(request, is_chat=False)

    @app.post("/api/chat")
    async def chat(request: Request):
        return await _handle_generate(request, is_chat=True)

    return app


app = create_app("config.yaml", "store.db", "events.jsonl")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_endpoints.py -v`
Expected: PASS (8 passed)

- [ ] **Step 5: Run the full suite**

Run: `pytest -v`
Expected: all tests across all files PASS

- [ ] **Step 6: Commit**

```bash
git add honeypot/main.py tests/test_endpoints.py
git commit -m "feat: wire FastAPI app with all honeypot endpoints"
```

---

### Task 8: Containerized deployment

**Files:**
- Create: `Dockerfile`
- Create: `docker-compose.yml`
- Create: `README.md`

**Interfaces:**
- Consumes: `honeypot.main:app`, `requirements.txt`, `config.yaml`.
- Produces: a `docker compose up` that runs real Ollama (private), the honeypot (public `:11434`), and pulls both models.

- [ ] **Step 1: Create `Dockerfile`**

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY honeypot ./honeypot
COPY config.yaml .
EXPOSE 11434
CMD ["uvicorn", "honeypot.main:app", "--host", "0.0.0.0", "--port", "11434"]
```

- [ ] **Step 2: Create `docker-compose.yml`**

```yaml
services:
  ollama:
    image: ollama/ollama:latest
    expose:
      - "11500"
    environment:
      - OLLAMA_HOST=0.0.0.0:11500
    volumes:
      - ollama_models:/root/.ollama
    restart: unless-stopped

  ollama-init:
    image: ollama/ollama:latest
    depends_on:
      - ollama
    environment:
      - OLLAMA_HOST=ollama:11500
    entrypoint: >
      sh -c "sleep 5 &&
             ollama pull qwen2.5:7b &&
             ollama pull qwen2.5:3b"
    restart: "no"

  honeypot:
    build: .
    depends_on:
      - ollama
    ports:
      - "11434:11434"
    volumes:
      - ./config.yaml:/app/config.yaml
      - honeypot_data:/app/data
    environment:
      - HONEYPOT_DB=/app/data/store.db
      - HONEYPOT_JSONL=/app/data/events.jsonl
    restart: unless-stopped

volumes:
  ollama_models:
  honeypot_data:
```

- [ ] **Step 3: Make DB/JSONL paths env-configurable in `honeypot/main.py`**

Replace the module-level app line at the bottom of `honeypot/main.py`:

```python
import os

app = create_app(
    os.environ.get("HONEYPOT_CONFIG", "config.yaml"),
    os.environ.get("HONEYPOT_DB", "store.db"),
    os.environ.get("HONEYPOT_JSONL", "events.jsonl"),
)
```

And set `real_ollama_url` in `config.yaml` for compose networking:

```yaml
real_ollama_url: "http://ollama:11500"
```

- [ ] **Step 4: Verify the app still imports with env overrides**

Run: `HONEYPOT_DB=/tmp/t.db HONEYPOT_JSONL=/tmp/t.jsonl python -c "import honeypot.main; print('ok')"`
Expected: prints `ok`

- [ ] **Step 5: Create `README.md`**

````markdown
# Ollama Honeypot

Deceptive Ollama-compatible service. See `docs/superpowers/specs/2026-06-22-ollama-honeypot-design.md`.

## Run (local dev)
```bash
pip install -r requirements.txt
uvicorn honeypot.main:app --host 0.0.0.0 --port 11434
```

## Run (VM, Docker)
```bash
docker compose up -d --build
```
Honeypot listens on `:11434` (public). Real Ollama stays private on `:11500`.
Logs in the `honeypot_data` volume (`store.db`, `events.jsonl`).

## Operator access
Reach the VM over netbird VPN, `ssh 10.20.0.64`. The admin dashboard
(separate plan) binds to `:8080` on the VPN interface only.
````

- [ ] **Step 6: Run full test suite once more**

Run: `pytest -v`
Expected: all PASS

- [ ] **Step 7: Commit**

```bash
git add Dockerfile docker-compose.yml README.md honeypot/main.py config.yaml
git commit -m "feat: containerized deployment with Ollama backend and model pulls"
```

---

## Self-Review

**Spec coverage:**
- §3 Architecture (reverse proxy, private Ollama) → Tasks 6, 7, 8 ✓
- §4.1 Endpoint table (real/fake per endpoint) → Task 7 ✓
- §4.2 Deterministic 30% routing, model honored, streaming → Tasks 4, 6, 7 ✓
- §4.3 Mocked endpoints (embed/version/static) → Task 3, wired in Task 7 ✓
- §5 Logging (SQLite + JSONL, all fields, body cap) → Tasks 2, 7 ✓
- §6 Guardrails (block → in-character refusal, logged) → Tasks 5, 7 ✓
- §8 Deployment (compose, both models) → Task 8 ✓
- §9 Testing (wire-format, distribution, determinism, guardrails, hot-reload) → Tasks 1–7 tests ✓
- §7 Dashboard → deliberately deferred to a separate plan (noted at top).

**Placeholder scan:** No TBD/TODO; every code step contains full code.

**Type consistency:** `should_fake`, `extract_prompt`, `fake_*`, `check`, `refusal_*`, `forward_json`, `stream_generate`, `ConfigStore.get`, `LoggingStore.log/recent` names match between their defining task and their use in Task 7. ✓

**Note on `@app.on_event`:** uses the simple lifecycle decorators for readability; if the pinned FastAPI version emits deprecation warnings, they do not affect behavior.
