"""
Configuration management for DeepWebHarvester.

Supports layered config: defaults → YAML file → environment variables → CLI flags.
Sensitive values (passwords) should always be supplied via environment variables,
never hard-coded in the config file.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml
from dotenv import load_dotenv

load_dotenv()


@dataclass
class TorConfig:
    """Tor network settings."""

    socks_host: str = "127.0.0.1"
    socks_port: int = 9050
    control_host: str = "127.0.0.1"
    control_port: int = 9051
    # Loaded from TOR_CONTROL_PASSWORD env var; never hard-coded
    control_password: str = ""
    renew_circuit_every: int = 10  # renew after N pages crawled


@dataclass
class CrawlerConfig:
    """Crawl behaviour settings."""

    max_depth: int = 2
    max_pages: int = 20
    crawl_delay: float = 7.0        # seconds between requests (be a good citizen)
    request_timeout: int = 30
    retry_count: int = 3
    backoff_factor: float = 4.0     # sleep = backoff * 2^attempt seconds
    max_workers: int = 3            # concurrent site crawlers
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
    )
    blacklist_paths: List[str] = field(
        default_factory=lambda: ["/register", "/login", "/signup", "/auth"]
    )


@dataclass
class StorageConfig:
    """Output/persistence settings."""

    output_dir: str = "results"
    json_output: bool = True
    csv_output: bool = True
    sqlite_output: bool = True
    db_name: str = "deepwebharvester.db"


@dataclass
class AppConfig:
    """Top-level application configuration."""

    tor: TorConfig = field(default_factory=TorConfig)
    crawler: CrawlerConfig = field(default_factory=CrawlerConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    seed_urls: List[str] = field(default_factory=list)
    log_level: str = "INFO"
    log_file: Optional[str] = None


def _apply_dict(obj: object, data: dict) -> None:
    """Apply key/value pairs from *data* onto *obj* for matching attributes."""
    for key, value in data.items():
        if hasattr(obj, key):
            setattr(obj, key, value)


def load_config(config_path: Optional[str] = None) -> AppConfig:
    """
    Load configuration from YAML file then override with environment variables.

    Priority (highest wins): env vars > YAML file > built-in defaults.

    Args:
        config_path: Optional path to a YAML configuration file.

    Returns:
        A fully populated :class:`AppConfig` instance.
    """
    cfg = AppConfig()

    # ── YAML layer ────────────────────────────────────────────────────────────
    if config_path:
        path = Path(config_path)
        if path.exists():
            with open(path, encoding="utf-8") as fh:
                data: dict = yaml.safe_load(fh) or {}

            _apply_dict(cfg.tor, data.get("tor", {}))
            _apply_dict(cfg.crawler, data.get("crawler", {}))
            _apply_dict(cfg.storage, data.get("storage", {}))
            cfg.seed_urls = data.get("seed_urls", cfg.seed_urls)
            cfg.log_level = data.get("log_level", cfg.log_level)
            cfg.log_file = data.get("log_file", cfg.log_file)

    # ── Environment variable layer ────────────────────────────────────────────
    if os.getenv("TOR_CONTROL_PASSWORD"):
        cfg.tor.control_password = os.environ["TOR_CONTROL_PASSWORD"]
    if os.getenv("TOR_SOCKS_PORT"):
        cfg.tor.socks_port = int(os.environ["TOR_SOCKS_PORT"])
    if os.getenv("TOR_CONTROL_PORT"):
        cfg.tor.control_port = int(os.environ["TOR_CONTROL_PORT"])
    if os.getenv("LOG_LEVEL"):
        cfg.log_level = os.environ["LOG_LEVEL"]
    if os.getenv("OUTPUT_DIR"):
        cfg.storage.output_dir = os.environ["OUTPUT_DIR"]

    return cfg
