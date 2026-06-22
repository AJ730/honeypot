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
