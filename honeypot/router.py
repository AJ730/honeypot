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
