"""
Redis-backed distributed cache and URL queue.

Enables multi-instance horizontal scaling:
  - Distributed content-hash deduplication (replaces in-process Set)
  - Shared URL queue (replaces per-process deque)
  - Job result caching with TTL
  - Graceful fallback to in-memory mode when Redis is unavailable

Configuration::

    REDIS_URL=redis://localhost:6379/0
    DWH_CACHE_TTL=86400          # seconds (default 24h)
    DWH_CACHE_KEY_PREFIX=dwh:
"""
from __future__ import annotations

import hashlib
import logging
import os
from typing import Optional, Set

logger = logging.getLogger(__name__)

try:
    import redis as redis_lib  # type: ignore[import]
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.debug("redis-py not installed — using in-process fallback cache.")


class _InMemoryCache:
    """Thread-safe in-memory fallback (single-process only)."""
    import threading as _threading

    def __init__(self) -> None:
        self._hashes: Set[str] = set()
        self._lock = self._threading.Lock()

    def is_duplicate(self, content_hash: str) -> bool:
        with self._lock:
            return content_hash in self._hashes

    def mark_seen(self, content_hash: str) -> None:
        with self._lock:
            self._hashes.add(content_hash)

    def is_url_crawled(self, url: str) -> bool:
        h = hashlib.sha1(url.encode()).hexdigest()
        with self._lock:
            return h in self._hashes

    def mark_url_crawled(self, url: str) -> None:
        h = hashlib.sha1(url.encode()).hexdigest()
        with self._lock:
            self._hashes.add(h)

    def flush(self) -> None:
        with self._lock:
            self._hashes.clear()

    @property
    def backend(self) -> str:
        return "memory"


class RedisCache:
    """
    Distributed cache backed by Redis.

    Uses Redis SET operations for O(1) deduplication across multiple
    crawler instances.  Falls back transparently to in-memory if Redis
    is unavailable.

    Usage::

        cache = RedisCache.from_env()
        if not cache.is_duplicate(content_hash):
            cache.mark_seen(content_hash)
            # process page
    """

    _PREFIX_HASH = "hash:"
    _PREFIX_URL  = "url:"

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        key_prefix: str = "dwh:",
        ttl: int = 86400,
    ) -> None:
        self._prefix = key_prefix
        self._ttl = ttl
        self._client: Optional[object] = None
        self._fallback = _InMemoryCache()

        if REDIS_AVAILABLE:
            try:
                client = redis_lib.from_url(
                    redis_url,
                    decode_responses=True,
                    socket_connect_timeout=3,
                    socket_timeout=3,
                )
                client.ping()  # type: ignore[attr-defined]
                self._client = client
                logger.info("Redis cache connected: %s", redis_url)
            except Exception as exc:
                logger.warning(
                    "Redis unavailable (%s) — falling back to in-memory cache.", exc
                )
        else:
            logger.info("redis-py not installed — using in-memory cache.")

    @classmethod
    def from_env(cls) -> "RedisCache":
        """Construct from environment variables."""
        return cls(
            redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            key_prefix=os.getenv("DWH_CACHE_KEY_PREFIX", "dwh:"),
            ttl=int(os.getenv("DWH_CACHE_TTL", "86400")),
        )

    @property
    def backend(self) -> str:
        return "redis" if self._client else "memory"

    def _key(self, prefix: str, value: str) -> str:
        return f"{self._prefix}{prefix}{value}"

    # ── Public interface ──────────────────────────────────────────────────────

    def is_duplicate(self, content_hash: str) -> bool:
        """Return True if this content hash has been seen before."""
        if self._client:
            try:
                return bool(
                    self._client.exists(  # type: ignore[attr-defined]
                        self._key(self._PREFIX_HASH, content_hash)
                    )
                )
            except Exception as exc:
                logger.warning("Redis read error: %s", exc)
        return self._fallback.is_duplicate(content_hash)

    def mark_seen(self, content_hash: str) -> None:
        """Record a content hash as seen."""
        if self._client:
            try:
                self._client.setex(  # type: ignore[attr-defined]
                    self._key(self._PREFIX_HASH, content_hash),
                    self._ttl,
                    "1",
                )
                return
            except Exception as exc:
                logger.warning("Redis write error: %s", exc)
        self._fallback.mark_seen(content_hash)

    def is_url_crawled(self, url: str) -> bool:
        """Return True if this URL has been crawled before."""
        url_hash = hashlib.sha1(url.encode()).hexdigest()
        if self._client:
            try:
                return bool(
                    self._client.exists(  # type: ignore[attr-defined]
                        self._key(self._PREFIX_URL, url_hash)
                    )
                )
            except Exception as exc:
                logger.warning("Redis read error: %s", exc)
        return self._fallback.is_url_crawled(url)

    def mark_url_crawled(self, url: str) -> None:
        """Mark a URL as crawled."""
        url_hash = hashlib.sha1(url.encode()).hexdigest()
        if self._client:
            try:
                self._client.setex(  # type: ignore[attr-defined]
                    self._key(self._PREFIX_URL, url_hash),
                    self._ttl,
                    "1",
                )
                return
            except Exception as exc:
                logger.warning("Redis write error: %s", exc)
        self._fallback.mark_url_crawled(url)

    def flush(self) -> int:
        """
        Flush all DeepWebHarvester keys from Redis.

        Returns the number of keys deleted.
        """
        if self._client:
            try:
                pattern = f"{self._prefix}*"
                keys = list(self._client.scan_iter(pattern))  # type: ignore[attr-defined]
                if keys:
                    self._client.delete(*keys)  # type: ignore[attr-defined]
                logger.info("Flushed %d cache keys from Redis.", len(keys))
                return len(keys)
            except Exception as exc:
                logger.warning("Redis flush error: %s", exc)
        self._fallback.flush()
        return 0

    def stats(self) -> dict:
        """Return basic cache statistics."""
        info: dict = {"backend": self.backend, "ttl_seconds": self._ttl}
        if self._client:
            try:
                pattern = f"{self._prefix}*"
                keys = list(self._client.scan_iter(pattern))  # type: ignore[attr-defined]
                info["total_keys"] = len(keys)
                info["hash_keys"] = sum(
                    1 for k in keys if self._PREFIX_HASH in k
                )
                info["url_keys"] = sum(
                    1 for k in keys if self._PREFIX_URL in k
                )
            except Exception:
                pass
        return info
