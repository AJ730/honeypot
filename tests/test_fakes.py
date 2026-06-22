from honeypot.fakes import (
    fake_embed, fake_version, fake_completion,
    CREATE_RESPONSE, PULL_RESPONSE, PUSH_RESPONSE, COPY_OK, DELETE_OK,
)


def test_fake_embed_shape_and_echo_model():
    body = {"model": "embeddinggemma", "input": "Why is the sky blue?"}
    out = fake_embed(body)
    assert out["model"] == "embeddinggemma"
    assert isinstance(out["embeddings"], list)
    assert isinstance(out["embeddings"][0], list)
    assert all(isinstance(x, float) for x in out["embeddings"][0])
    assert out["prompt_eval_count"] >= 1
    assert out["total_duration"] > 0
    assert out["load_duration"] > 0


def test_fake_embed_scales_with_input():
    short = fake_embed({"model": "m", "input": "hi"})
    long = fake_embed({"model": "m", "input": "word " * 200})
    assert long["prompt_eval_count"] > short["prompt_eval_count"]


def test_fake_version_deterministic_per_ip():
    versions = ["0.1.20", "0.5.7", "0.12.6"]
    a = fake_version("1.2.3.4", versions)
    b = fake_version("1.2.3.4", versions)
    assert a == b
    assert a in versions


def test_fake_version_varies_across_ips():
    versions = ["0.1.20", "0.3.6", "0.5.7", "0.9.0", "0.11.4", "0.12.6"]
    seen = {fake_version(f"10.0.0.{i}", versions) for i in range(50)}
    assert len(seen) > 1


def test_static_responses():
    assert CREATE_RESPONSE == {"status": "success"}
    assert PULL_RESPONSE == {"status": "success"}
    assert PUSH_RESPONSE == {"status": "success"}
    assert COPY_OK == "200 OK"
    assert DELETE_OK == "Model successfully deleted"


def test_fake_completion_shape_and_determinism():
    body = {"model": "qwen2.5:7b", "prompt": "explain TLS"}
    a = fake_completion(body, ["resp-a", "resp-b"])
    b = fake_completion(body, ["resp-a", "resp-b"])
    assert a["response"] == b["response"]
    assert a["model"] == "qwen2.5:7b"
    assert a["done"] is True
    assert a["response"] in ("resp-a", "resp-b")
