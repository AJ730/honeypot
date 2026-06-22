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
