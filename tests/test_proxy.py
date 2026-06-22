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
