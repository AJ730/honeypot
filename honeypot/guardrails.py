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
