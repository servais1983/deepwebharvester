"""Tests for async_crawler.py — without a live Tor network."""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

try:
    import aiohttp
    from deepwebharvester.async_crawler import (
        AsyncCrawler,
        AsyncCrawlerConfig,
        run_async_crawl,
    )
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from deepwebharvester.extractor import PageExtractor

pytestmark = pytest.mark.skipif(
    not AIOHTTP_AVAILABLE, reason="aiohttp not installed"
)

_SAMPLE_HTML = """
<html><head><title>Test .onion</title></head>
<body><p>Hello world</p>
<a href="http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/page2">link</a>
</body></html>
"""

_VALID_ONION = "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/"


def _make_tor_manager():
    m = MagicMock()
    m.proxy_url = "socks5h://127.0.0.1:9050"
    sess = MagicMock()
    sess.headers = {"User-Agent": "test"}
    m.create_session.return_value = sess
    m.renew_circuit.return_value = True
    return m


def _make_extractor():
    return PageExtractor(blacklist_paths=["/login"])


@pytest.mark.asyncio
async def test_async_crawler_context_manager():
    tor = _make_tor_manager()
    ext = _make_extractor()
    cfg = AsyncCrawlerConfig(max_pages=1, crawl_delay=0)

    with patch("deepwebharvester.async_crawler.ProxyConnector") as mock_conn:
        mock_conn.from_url.return_value = MagicMock()
        with patch("deepwebharvester.async_crawler.aiohttp.ClientSession") as mock_sess:
            mock_sess.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            mock_sess.return_value.__aexit__ = AsyncMock(return_value=None)
            mock_sess.return_value.close = AsyncMock()
            async with AsyncCrawler(tor, ext, cfg) as crawler:
                assert crawler is not None


@pytest.mark.asyncio
async def test_no_aiohttp_raises_import_error():
    import deepwebharvester.async_crawler as m
    orig = m.AIOHTTP_AVAILABLE
    m.AIOHTTP_AVAILABLE = False
    try:
        with pytest.raises(ImportError):
            AsyncCrawler(MagicMock(), MagicMock())
    finally:
        m.AIOHTTP_AVAILABLE = orig


@pytest.mark.asyncio
async def test_async_crawler_config_defaults():
    cfg = AsyncCrawlerConfig()
    assert cfg.max_depth == 2
    assert cfg.max_pages == 20
    assert cfg.crawl_delay == 5.0
    assert cfg.max_concurrent_domains == 5


@pytest.mark.asyncio
async def test_throttle_enforces_delay():
    """Throttle should wait if called twice in quick succession."""
    import time
    tor = _make_tor_manager()
    ext = _make_extractor()
    cfg = AsyncCrawlerConfig(crawl_delay=0.05)

    crawler = AsyncCrawler.__new__(AsyncCrawler)
    crawler._cfg = cfg
    crawler._domain_last_request = {}
    crawler._domain_locks = {}

    import collections
    crawler._domain_last_request = collections.defaultdict(float)
    crawler._domain_locks = collections.defaultdict(asyncio.Lock)

    # First call should not wait, second should wait ~0.05s
    t0 = time.monotonic()
    await crawler._throttle("test.onion")
    await crawler._throttle("test.onion")
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.04  # at least ~1 delay period
