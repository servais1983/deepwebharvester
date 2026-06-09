"""Tests for cache.py — in-memory fallback and Redis client."""
import pytest
from unittest.mock import MagicMock, patch

from deepwebharvester.cache import RedisCache, _InMemoryCache


class TestInMemoryCache:
    def test_mark_and_is_duplicate(self):
        c = _InMemoryCache()
        assert not c.is_duplicate("hash123")
        c.mark_seen("hash123")
        assert c.is_duplicate("hash123")

    def test_url_crawled(self):
        c = _InMemoryCache()
        url = "http://abc.onion/"
        assert not c.is_url_crawled(url)
        c.mark_url_crawled(url)
        assert c.is_url_crawled(url)

    def test_flush(self):
        c = _InMemoryCache()
        c.mark_seen("h1")
        c.mark_seen("h2")
        c.flush()
        assert not c.is_duplicate("h1")
        assert not c.is_duplicate("h2")

    def test_backend_name(self):
        assert _InMemoryCache().backend == "memory"


class TestRedisCacheFallback:
    """When Redis is unavailable, operations fall back to in-memory."""

    def test_falls_back_to_memory_on_connection_error(self):
        with patch("deepwebharvester.cache.REDIS_AVAILABLE", True):
            with patch("deepwebharvester.cache.redis_lib") as mock_redis:
                mock_redis.from_url.return_value.ping.side_effect = Exception("refused")
                cache = RedisCache(redis_url="redis://localhost:9999/0")
        assert cache.backend == "memory"

    def test_dedup_in_memory_fallback(self):
        cache = RedisCache.__new__(RedisCache)
        cache._client = None
        cache._prefix = "dwh:"
        cache._ttl = 3600
        from deepwebharvester.cache import _InMemoryCache
        cache._fallback = _InMemoryCache()

        assert not cache.is_duplicate("abc")
        cache.mark_seen("abc")
        assert cache.is_duplicate("abc")

    def test_url_tracking_in_memory_fallback(self):
        cache = RedisCache.__new__(RedisCache)
        cache._client = None
        cache._prefix = "dwh:"
        cache._ttl = 3600
        from deepwebharvester.cache import _InMemoryCache
        cache._fallback = _InMemoryCache()

        url = "http://test.onion/page"
        assert not cache.is_url_crawled(url)
        cache.mark_url_crawled(url)
        assert cache.is_url_crawled(url)

    def test_backend_name_memory(self):
        cache = RedisCache.__new__(RedisCache)
        cache._client = None
        assert cache.backend == "memory"

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/1")
        monkeypatch.setenv("DWH_CACHE_TTL", "7200")
        with patch("deepwebharvester.cache.REDIS_AVAILABLE", False):
            cache = RedisCache.from_env()
        assert cache._ttl == 7200

    def test_flush_no_client(self):
        cache = RedisCache.__new__(RedisCache)
        cache._client = None
        cache._prefix = "dwh:"
        cache._ttl = 3600
        from deepwebharvester.cache import _InMemoryCache
        cache._fallback = _InMemoryCache()
        result = cache.flush()
        assert result == 0

    def test_stats_no_client(self):
        cache = RedisCache.__new__(RedisCache)
        cache._client = None
        cache._prefix = "dwh:"
        cache._ttl = 3600
        from deepwebharvester.cache import _InMemoryCache
        cache._fallback = _InMemoryCache()
        s = cache.stats()
        assert s["backend"] == "memory"
        assert s["ttl_seconds"] == 3600


# ── Redis-backed paths ─────────────────────────────────────────────────────

def _make_redis_cache_with_mock_client():
    """Return a RedisCache with a fake Redis client injected."""
    import unittest.mock as mock
    from deepwebharvester.cache import RedisCache
    cache = RedisCache.__new__(RedisCache)
    cache._prefix = "dwh:"
    cache._ttl = 3600
    cache._fallback = cache.__class__.__new__(cache.__class__)
    from deepwebharvester.cache import _InMemoryCache
    cache._fallback = _InMemoryCache()
    mock_client = mock.MagicMock()
    cache._client = mock_client
    return cache, mock_client


def test_redis_is_duplicate_hit():
    from deepwebharvester.cache import RedisCache
    cache, mc = _make_redis_cache_with_mock_client()
    mc.exists.return_value = 1
    assert cache.is_duplicate("abc123") is True
    mc.exists.assert_called_once()


def test_redis_is_duplicate_miss():
    cache, mc = _make_redis_cache_with_mock_client()
    mc.exists.return_value = 0
    assert cache.is_duplicate("xyz") is False


def test_redis_mark_seen():
    cache, mc = _make_redis_cache_with_mock_client()
    cache.mark_seen("hash1")
    mc.setex.assert_called_once()


def test_redis_is_url_crawled():
    cache, mc = _make_redis_cache_with_mock_client()
    mc.exists.return_value = 1
    assert cache.is_url_crawled("http://example.onion/") is True


def test_redis_mark_url_crawled():
    cache, mc = _make_redis_cache_with_mock_client()
    cache.mark_url_crawled("http://example.onion/page")
    mc.setex.assert_called_once()


def test_redis_flush_with_keys():
    cache, mc = _make_redis_cache_with_mock_client()
    mc.scan_iter.return_value = ["dwh:h:a", "dwh:u:b"]
    n = cache.flush()
    assert n == 2
    mc.delete.assert_called_once()


def test_redis_flush_no_keys():
    cache, mc = _make_redis_cache_with_mock_client()
    mc.scan_iter.return_value = []
    n = cache.flush()
    assert n == 0


def test_redis_stats():
    cache, mc = _make_redis_cache_with_mock_client()
    mc.scan_iter.return_value = ["dwh:h:aaa", "dwh:u:bbb"]
    info = cache.stats()
    assert info["backend"] == "redis"
    assert info["total_keys"] == 2


def test_redis_read_error_falls_back():
    """Redis read error should fall back to in-memory."""
    import redis as redis_lib
    cache, mc = _make_redis_cache_with_mock_client()
    mc.exists.side_effect = Exception("connection lost")
    # Should not raise; falls back to in-memory (returns False for unknown)
    result = cache.is_duplicate("fallback_hash")
    assert result is False


def test_redis_write_error_falls_back():
    """Redis write error should fall back to in-memory mark_seen."""
    cache, mc = _make_redis_cache_with_mock_client()
    mc.setex.side_effect = Exception("timeout")
    cache.mark_seen("fallback_write")  # must not raise
    # Verify fallback has it
    assert cache._fallback.is_duplicate("fallback_write") is True


def test_backend_property_no_client():
    from deepwebharvester.cache import RedisCache, _InMemoryCache
    cache = RedisCache.__new__(RedisCache)
    cache._prefix = "dwh:"
    cache._ttl = 3600
    cache._fallback = _InMemoryCache()
    cache._client = None
    assert cache.backend == "memory"
