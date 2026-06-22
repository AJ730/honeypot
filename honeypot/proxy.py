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
        async for chunk in resp.aiter_bytes():
            yield chunk
