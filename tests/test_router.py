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
