import os
import time
import pytest
from honeypot.config import Config, ConfigStore


def _bump_mtime(path, offset=1):
    os.utime(path, (time.time() + offset, time.time() + offset))


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
    _bump_mtime(cfg_path)
    assert store.get().fake_pct == 50


def test_bad_reload_keeps_last_good_config(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    write_yaml(cfg_path, fake_pct=30)
    store = ConfigStore(str(cfg_path))
    assert store.get().fake_pct == 30
    # simulate a bad live edit (malformed YAML)
    cfg_path.write_text("fake_pct: 30\n  bad: : indent")
    _bump_mtime(cfg_path, offset=2)
    # must NOT raise; keeps serving the last-good config
    assert store.get().fake_pct == 30
    # once fixed, it picks up the new value
    write_yaml(cfg_path, fake_pct=70)
    _bump_mtime(cfg_path, offset=4)
    assert store.get().fake_pct == 70


def test_non_mapping_config_keeps_last_good(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    write_yaml(cfg_path, fake_pct=30)
    store = ConfigStore(str(cfg_path))
    store.get()
    cfg_path.write_text("- just\n- a\n- list\n")  # valid YAML, wrong shape
    _bump_mtime(cfg_path, offset=2)
    assert store.get().fake_pct == 30  # no crash, last-good retained


def test_first_load_failure_raises(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("not: valid: config")  # malformed, no last-good
    store = ConfigStore(str(cfg_path))
    with pytest.raises(Exception):
        store.get()
