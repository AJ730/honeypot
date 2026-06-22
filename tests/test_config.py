import time
from honeypot.config import Config, ConfigStore


def write_yaml(path, fake_pct=30):
    path.write_text(
        "fake_pct: %d\n"
        "real_ollama_url: \"http://127.0.0.1:11500\"\n"
        "default_model: \"qwen2.5:7b\"\n"
        "advertised_models: [\"qwen2.5:7b\"]\n"
        "versions: [\"0.12.6\"]\n"
        "guardrail_patterns: [\"phishing\"]\n"
        "fake_responses: [\"hi\"]\n"
        "max_body_bytes: 65536\n" % fake_pct
    )


def test_loads_config(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    write_yaml(cfg_path)
    store = ConfigStore(str(cfg_path))
    cfg = store.get()
    assert isinstance(cfg, Config)
    assert cfg.fake_pct == 30
    assert cfg.default_model == "qwen2.5:7b"
    assert cfg.advertised_models == ["qwen2.5:7b"]


def test_hot_reload_on_mtime_change(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    write_yaml(cfg_path, fake_pct=30)
    store = ConfigStore(str(cfg_path))
    assert store.get().fake_pct == 30
    time.sleep(0.01)
    write_yaml(cfg_path, fake_pct=50)
    # bump mtime explicitly to be filesystem-independent
    import os
    os.utime(cfg_path, (time.time() + 1, time.time() + 1))
    assert store.get().fake_pct == 50
