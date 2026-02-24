"""
Shared pytest fixtures for the DeepWebHarvester test suite.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from deepwebharvester.crawler import Crawler
from deepwebharvester.extractor import PageExtractor
from deepwebharvester.storage import StorageManager

# ── Constants used across tests ───────────────────────────────────────────────

# Tor v3 .onion addresses require exactly 56 base32 chars [a-z2-7]
VALID_ONION = "http://" + "a" * 56 + ".onion"
VALID_ONION_2 = "http://" + "b" * 56 + ".onion"

SAMPLE_HTML = f"""<!DOCTYPE html>
<html>
<head><title>Dark OSINT Research Site</title></head>
<body>
  <h1>Welcome</h1>
  <p>Legitimate research content for OSINT testing.</p>
  <a href="{VALID_ONION}/page2">Internal link</a>
  <a href="{VALID_ONION_2}/">Different site</a>
  <a href="/relative-page">Relative link</a>
  <a href="https://clearweb.example.com/">Clear-web link (should be excluded)</a>
  <script>alert('injected script - should be stripped')</script>
</body>
</html>"""


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def extractor() -> PageExtractor:
    return PageExtractor(blacklist_paths=["/login", "/register", "/signup"])


@pytest.fixture
def mock_tor_manager() -> MagicMock:
    """TorManager mock that returns a session pre-configured with a fake response."""
    manager = MagicMock()
    session = MagicMock()
    response = MagicMock()
    response.text = SAMPLE_HTML
    response.raise_for_status.return_value = None
    session.get.return_value = response
    manager.create_session.return_value = session
    manager.renew_circuit.return_value = True
    manager.proxy_url = "socks5h://127.0.0.1:9050"
    return manager


@pytest.fixture
def fast_crawler(mock_tor_manager: MagicMock, extractor: PageExtractor) -> Crawler:
    """Crawler configured for fast unit-test execution (no delays, no retries)."""
    return Crawler(
        tor_manager=mock_tor_manager,
        extractor=extractor,
        max_depth=1,
        max_pages=5,
        crawl_delay=0.0,
        request_timeout=5,
        retry_count=1,
        backoff_factor=0.0,
        renew_circuit_every=1000,
        max_workers=1,
    )


@pytest.fixture
def tmp_storage(tmp_path) -> StorageManager:
    """StorageManager writing to a temporary directory."""
    return StorageManager(
        output_dir=str(tmp_path),
        db_name="test.db",
        json_output=True,
        csv_output=True,
        sqlite_output=True,
    )
