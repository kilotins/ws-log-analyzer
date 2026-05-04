"""Tests for logpilot.config — AppConfig env-var overrides and defaults."""
from __future__ import annotations

import os
from pathlib import Path


def test_app_config_uses_env_overrides(monkeypatch, tmp_path):
    monkeypatch.setenv("LOGPILOT_BASE_DIR", str(tmp_path))
    monkeypatch.setenv("LOGPILOT_UPLOADS_DIR", str(tmp_path / "custom-uploads"))

    # Re-import so from_env() picks up the patched env
    import importlib
    import logpilot.config as cfg_mod
    importlib.reload(cfg_mod)
    cfg = cfg_mod.AppConfig.from_env()

    assert cfg.base_dir == tmp_path
    assert cfg.uploads_dir == tmp_path / "custom-uploads"
    # cache_dir not overridden — should fall back to base / "cache"
    assert cfg.cache_dir == tmp_path / "cache"

    # Restore module state
    importlib.reload(cfg_mod)


def test_app_config_defaults_without_env(monkeypatch, tmp_path):
    # Clear all LOGPILOT_ env vars so we test pure-default path
    for k in list(os.environ):
        if k.startswith("LOGPILOT_"):
            monkeypatch.delenv(k, raising=False)

    import importlib
    import logpilot.config as cfg_mod
    importlib.reload(cfg_mod)
    cfg = cfg_mod.AppConfig.from_env(default_base=tmp_path)

    assert cfg.base_dir == tmp_path
    assert cfg.uploads_dir == tmp_path / "uploads"
    assert cfg.reports_dir == tmp_path / "reports"
    assert cfg.cache_dir == tmp_path / "cache"
    assert cfg.logs_dir == tmp_path / "logs"
    assert cfg.api_keys_file == tmp_path / ".api_keys.json"
    assert cfg.license_key_file == tmp_path / ".license_key"
    assert cfg.theme_file == tmp_path / ".theme.json"
    assert cfg.local_ai_settings_file == tmp_path / ".local_ai_settings.json"
    assert cfg.keyring_file == tmp_path / ".keyring.json"

    importlib.reload(cfg_mod)


def test_ensure_dirs_creates_directories(tmp_path):
    import importlib
    import logpilot.config as cfg_mod
    importlib.reload(cfg_mod)

    cfg = cfg_mod.AppConfig.from_env(default_base=tmp_path)
    cfg.ensure_dirs()

    assert (tmp_path / "uploads").is_dir()
    assert (tmp_path / "reports").is_dir()
    assert (tmp_path / "cache").is_dir()
    assert (tmp_path / "logs").is_dir()
