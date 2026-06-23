import httpx
import pytest

from honeypot.guardrails import parse_guard_verdict, llm_check


def test_parse_safe():
    assert parse_guard_verdict("safe") is None
    assert parse_guard_verdict("Safe\n") is None


def test_parse_unsafe_with_category():
    assert parse_guard_verdict("unsafe\nS2") == "llm:S2"
    assert parse_guard_verdict("unsafe\nS2,S9") == "llm:S2,S9"


def test_parse_unsafe_bare():
    assert parse_guard_verdict("unsafe") == "llm:unsafe"


def test_parse_empty_or_ambiguous_fails_open():
    assert parse_guard_verdict("") is None
    assert parse_guard_verdict("I'm not sure") is None


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_llm_check_blocks_unsafe():
    def handler(request):
        assert request.url.path == "/api/chat"
        return httpx.Response(200, json={"message": {"content": "unsafe\nS2"}})
    async with _client(handler) as c:
        assert await llm_check(c, "http://up", "llama-guard3:1b", "do crime") == "llm:S2"


@pytest.mark.asyncio
async def test_llm_check_allows_safe():
    def handler(request):
        return httpx.Response(200, json={"message": {"content": "safe"}})
    async with _client(handler) as c:
        assert await llm_check(c, "http://up", "llama-guard3:1b", "explain TLS") is None


@pytest.mark.asyncio
async def test_llm_check_fails_open_on_error():
    def handler(request):
        return httpx.Response(500, text="backend down")
    async with _client(handler) as c:
        assert await llm_check(c, "http://up", "llama-guard3:1b", "anything") is None


@pytest.mark.asyncio
async def test_llm_check_empty_prompt_skips():
    async with _client(lambda r: httpx.Response(200, json={})) as c:
        assert await llm_check(c, "http://up", "llama-guard3:1b", "") is None
