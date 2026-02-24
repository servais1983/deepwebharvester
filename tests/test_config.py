"""
Tests for configuration loading and environment variable overrides.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from deepwebharvester.config import AppConfig, TorConfig, CrawlerConfig, StorageConfig, load_config


# ── Defaults ──────────────────────────────────────────────────────────────────


class TestDefaults:
    def test_tor_defaults(self) -> None:
        cfg = AppConfig()
        assert cfg.tor.socks_port == 9050
        assert cfg.tor.control_port == 9051
        assert cfg.tor.control_password == ""

    def test_crawler_defaults(self) -> None:
        cfg = AppConfig()
        assert cfg.crawler.max_depth == 2
        assert cfg.crawler.max_pages == 20
        assert cfg.crawler.crawl_delay == 7.0
        assert cfg.crawler.retry_count == 3

    def test_storage_defaults(self) -> None:
        cfg = AppConfig()
        assert cfg.storage.json_output is True
        assert cfg.storage.csv_output is True
        assert cfg.storage.sqlite_output is True


# ── YAML loading ──────────────────────────────────────────────────────────────


class TestYamlLoading:
    def test_loads_tor_settings(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({
            "tor": {"socks_port": 19050, "control_port": 19051},
        }))
        cfg = load_config(str(config_file))
        assert cfg.tor.socks_port == 19050
        assert cfg.tor.control_port == 19051

    def test_loads_crawler_settings(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({
            "crawler": {"max_depth": 5, "max_pages": 100, "crawl_delay": 3.0},
        }))
        cfg = load_config(str(config_file))
        assert cfg.crawler.max_depth == 5
        assert cfg.crawler.max_pages == 100
        assert cfg.crawler.crawl_delay == 3.0

    def test_loads_seed_urls(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        url = "http://aaaabbbbccccddddeeeeffffgggghhhh11112222333344445555.onion"
        config_file.write_text(yaml.dump({"seed_urls": [url]}))
        cfg = load_config(str(config_file))
        assert url in cfg.seed_urls

    def test_loads_log_level(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({"log_level": "DEBUG"}))
        cfg = load_config(str(config_file))
        assert cfg.log_level == "DEBUG"

    def test_nonexistent_file_uses_defaults(self) -> None:
        cfg = load_config("/nonexistent/path/config.yaml")
        assert cfg.tor.socks_port == 9050

    def test_empty_yaml_uses_defaults(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text("")
        cfg = load_config(str(config_file))
        assert cfg.crawler.max_depth == 2


# ── Environment variable overrides ────────────────────────────────────────────


class TestEnvOverrides:
    def test_tor_password_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TOR_CONTROL_PASSWORD", "supersecret")
        cfg = load_config()
        assert cfg.tor.control_password == "supersecret"

    def test_socks_port_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TOR_SOCKS_PORT", "19050")
        cfg = load_config()
        assert cfg.tor.socks_port == 19050

    def test_control_port_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TOR_CONTROL_PORT", "19051")
        cfg = load_config()
        assert cfg.tor.control_port == 19051

    def test_log_level_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")
        cfg = load_config()
        assert cfg.log_level == "DEBUG"

    def test_env_overrides_yaml(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({"log_level": "WARNING"}))
        monkeypatch.setenv("LOG_LEVEL", "ERROR")
        cfg = load_config(str(config_file))
        assert cfg.log_level == "ERROR"
