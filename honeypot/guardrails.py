from __future__ import annotations

import datetime

_REFUSAL_TEXT = (
    "I can't help with that. It appears to involve activity that could cause "
    "harm or break the law, so I won't assist. If there's a safe, legitimate "
    "task I can help with instead, let me know."
)


def _now_ts() -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond:06d}Z"


def check(prompt: str, patterns: list[str]) -> str | None:
    text = prompt if isinstance(prompt, str) else (str(prompt) if prompt else "")
    low = text.lower()
    for pat in patterns:
        if pat.lower() in low:
            return pat
    return None


def parse_guard_verdict(content: str) -> str | None:
    """Parse a Llama-Guard-style reply. Returns a trip reason ('llm:<cats>') if
    unsafe, else None. Anything that isn't a clear 'unsafe' fails open (None)."""
    if not content:
        return None
    text = content.strip()
    low = text.lower()
    if low.startswith("safe"):
        return None
    if low.startswith("unsafe"):
        rest = text[len("unsafe"):].strip().strip(":").strip()
        cats = ",".join(p.strip() for p in rest.replace("\n", ",").split(",") if p.strip())
        return f"llm:{cats}" if cats else "llm:unsafe"
    return None


async def llm_check(client, ollama_url: str, model: str, prompt: str,
                    timeout: float = 8.0) -> str | None:
    """Ask an LLM safety classifier (e.g. Llama Guard 3) whether *prompt* is
    unsafe. Returns a trip reason if unsafe, else None. Fails open on any error
    or timeout — a classifier outage must never break the honeypot."""
    if not prompt or not str(prompt).strip():
        return None
    try:
        resp = await client.post(
            f"{ollama_url}/api/chat",
            json={"model": model,
                  "messages": [{"role": "user", "content": str(prompt)}],
                  "stream": False},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return None
        content = (resp.json().get("message") or {}).get("content", "")
    except Exception:
        return None
    return parse_guard_verdict(content)


def refusal_response(model: str) -> dict:
    return {
        "model": model,
        "created_at": _now_ts(),
        "response": _REFUSAL_TEXT,
        "done": True,
        "done_reason": "stop",
    }


def refusal_chat_response(model: str) -> dict:
    return {
        "model": model,
        "created_at": _now_ts(),
        "message": {"role": "assistant", "content": _REFUSAL_TEXT},
        "done": True,
        "done_reason": "stop",
    }
