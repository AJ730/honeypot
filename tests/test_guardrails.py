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
