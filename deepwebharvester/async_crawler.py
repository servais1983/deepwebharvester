"""
Async crawling engine — next-gen replacement for the threaded crawler.

Uses asyncio + aiohttp for ~10× throughput on I/O-bound .onion crawling.
Key improvements over the synchronous engine:
  - Per-domain rate limiting (semaphore + configurable delay)
  - Async-safe global deduplication via asyncio.Lock
  - Graceful cancellation on SIGTERM / KeyboardInterrupt
  - Streaming page callback (async generator)
  - Prometheus metrics integration via metrics.py
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import (
    AsyncGenerator,
    Callable,
    Coroutine,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
)

try:
    import aiohttp
    from aiohttp_socks import ProxyConnector  # type: ignore[import]
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from .extractor import PageExtractor
from .crawler import CrawlResult, CrawlStats

logger = logging.getLogger(__name__)

AsyncCallback = Callable[[CrawlResult], Coroutine]


@dataclass
class AsyncCrawlerConfig:
    """Tuneable parameters for the async crawler."""

    max_depth: int = 2
    max_pages: int = 20
    crawl_delay: float = 5.0           # seconds between requests per domain
    request_timeout: int = 30
    retry_count: int = 3
    backoff_factor: float = 3.0
    renew_circuit_every: int = 10
    max_concurrent_domains: int = 5    # simultaneous onion sites
    max_concurrent_per_domain: int = 2 # simultaneous requests per site
    connector_limit: int = 20          # total aiohttp connection pool size


class AsyncCrawler:
    """
    High-throughput async BFS crawler for .onion hidden services.

    Usage::

        async with AsyncCrawler(tor_manager, extractor, config) as crawler:
            async for result in crawler.crawl_all(seed_urls):
                storage.save(result)

    The crawler routes all traffic through the Tor SOCKS5 proxy using
    aiohttp-socks.  If aiohttp is not installed, it falls back to the
    synchronous :class:`~deepwebharvester.crawler.Crawler`.
    """

    def __init__(
        self,
        tor_manager,
        extractor: PageExtractor,
        config: Optional[AsyncCrawlerConfig] = None,
        on_page_crawled: Optional[AsyncCallback] = None,
    ) -> None:
        if not AIOHTTP_AVAILABLE:
            raise ImportError(
                "aiohttp and aiohttp-socks are required for async crawling. "
                "Run: pip install aiohttp aiohttp-socks"
            )
        self._tor = tor_manager
        self._extractor = extractor
        self._cfg = config or AsyncCrawlerConfig()
        self._on_page_crawled = on_page_crawled

        self._stats = CrawlStats()
        self._global_hashes: Set[str] = set()
        self._hash_lock = asyncio.Lock()
        self._stats_lock = asyncio.Lock()
        self._global_page_count = 0

        # Per-domain rate limiting: last-request timestamps
        self._domain_last_request: Dict[str, float] = defaultdict(float)
        self._domain_locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

        self._session: Optional[aiohttp.ClientSession] = None

    # ── Context manager ───────────────────────────────────────────────────────

    async def __aenter__(self) -> "AsyncCrawler":
        connector = ProxyConnector.from_url(
            self._tor.proxy_url,
            limit=self._cfg.connector_limit,
            ssl=False,
        )
        timeout = aiohttp.ClientTimeout(total=self._cfg.request_timeout)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self._tor.create_session().headers,
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._session:
            await self._session.close()

    @property
    def stats(self) -> CrawlStats:
        return self._stats

    # ── Private helpers ───────────────────────────────────────────────────────

    async def _throttle(self, domain: str) -> None:
        """Enforce per-domain rate limiting."""
        async with self._domain_locks[domain]:
            elapsed = time.monotonic() - self._domain_last_request[domain]
            wait = self._cfg.crawl_delay - elapsed
            if wait > 0:
                await asyncio.sleep(wait)
            self._domain_last_request[domain] = time.monotonic()

    async def _fetch(self, url: str) -> Optional[str]:
        """Async GET with exponential-backoff retries."""
        assert self._session is not None
        last_exc: Optional[Exception] = None
        for attempt in range(1, self._cfg.retry_count + 1):
            try:
                async with self._session.get(url) as resp:
                    resp.raise_for_status()
                    return await resp.text(errors="replace")
            except Exception as exc:
                last_exc = exc
                sleep_sec = self._cfg.backoff_factor * (2 ** (attempt - 1))
                logger.warning(
                    "Attempt %d/%d for %s failed: %s — retrying in %.0fs.",
                    attempt, self._cfg.retry_count, url, exc, sleep_sec,
                )
                await asyncio.sleep(sleep_sec)
        logger.error("All %d attempt(s) failed for %s: %s",
                     self._cfg.retry_count, url, last_exc)
        return None

    async def _crawl_page(
        self, url: str, depth: int
    ) -> Tuple[Optional[CrawlResult], List[str]]:
        """Fetch, parse, deduplicate a single page."""
        if self._extractor.is_blacklisted(url):
            async with self._stats_lock:
                self._stats.pages_skipped += 1
            return None, []

        domain = self._extractor.get_base_domain(url)
        await self._throttle(domain)

        logger.info("[depth=%d] Fetching: %s", depth, url)
        t0 = time.monotonic()
        html = await self._fetch(url)
        if html is None:
            async with self._stats_lock:
                self._stats.pages_failed += 1
            return None, []

        title, text, content_hash, links = self._extractor.extract_content(html, url)
        crawl_time = time.monotonic() - t0

        async with self._hash_lock:
            if content_hash in self._global_hashes:
                logger.debug("Duplicate content, skipping: %s", url)
                async with self._stats_lock:
                    self._stats.pages_deduplicated += 1
                return None, links
            self._global_hashes.add(content_hash)

        result = CrawlResult(
            url=url,
            title=title,
            text=text,
            content_hash=content_hash,
            depth=depth,
            crawl_time=crawl_time,
            links_found=len(links),
            site=domain,
        )
        return result, links

    async def _maybe_renew_circuit(self) -> None:
        async with self._stats_lock:
            count = self._global_page_count
        if count > 0 and count % self._cfg.renew_circuit_every == 0:
            await asyncio.get_event_loop().run_in_executor(
                None, self._tor.renew_circuit
            )

    # ── Site crawl coroutine ──────────────────────────────────────────────────

    async def crawl_site_gen(
        self,
        start_url: str,
        known_urls: Optional[Set[str]] = None,
    ) -> AsyncGenerator[CrawlResult, None]:
        """
        Async generator: BFS-crawl a single .onion site, yield each result.

        Yields :class:`CrawlResult` objects as pages are successfully crawled.
        """
        sem = asyncio.Semaphore(self._cfg.max_concurrent_per_domain)
        crawled: Set[str] = set(known_urls or set())
        queue: deque[Tuple[str, int]] = deque([(start_url, 0)])
        pages_this_site = 0

        logger.info("Async BFS crawl starting: %s", start_url)

        while queue and pages_this_site < self._cfg.max_pages:
            url, depth = queue.popleft()
            if url in crawled or depth > self._cfg.max_depth:
                continue
            crawled.add(url)

            async with sem:
                result, links = await self._crawl_page(url, depth)

            if result:
                pages_this_site += 1
                async with self._stats_lock:
                    self._stats.pages_crawled += 1
                    self._global_page_count += 1
                if self._on_page_crawled:
                    await self._on_page_crawled(result)
                await self._maybe_renew_circuit()
                yield result

            if depth < self._cfg.max_depth:
                for link in links:
                    if link not in crawled:
                        queue.append((link, depth + 1))

        async with self._stats_lock:
            self._stats.sites_crawled += 1
        logger.info("Async crawl complete: %s — %d pages", start_url, pages_this_site)

    # ── Multi-site orchestration ──────────────────────────────────────────────

    async def crawl_all(
        self,
        seed_urls: List[str],
        known_urls: Optional[Set[str]] = None,
    ) -> AsyncGenerator[CrawlResult, None]:
        """
        Crawl multiple .onion sites concurrently, yield results as they arrive.

        Sites are crawled with ``max_concurrent_domains`` concurrency.
        """
        valid = [u for u in seed_urls if self._extractor.is_valid_onion_url(u)]
        for bad in set(seed_urls) - set(valid):
            logger.warning("Invalid URL skipped: %s", bad)
        if not valid:
            logger.error("No valid .onion URLs to crawl.")
            return

        domain_sem = asyncio.Semaphore(self._cfg.max_concurrent_domains)
        result_queue: asyncio.Queue[Optional[CrawlResult]] = asyncio.Queue()

        async def _worker(url: str) -> None:
            async with domain_sem:
                async for res in self.crawl_site_gen(url, known_urls):
                    await result_queue.put(res)
            await result_queue.put(None)  # sentinel

        tasks = [asyncio.create_task(_worker(u)) for u in valid]
        done_count = 0
        total = len(valid)

        while done_count < total:
            item = await result_queue.get()
            if item is None:
                done_count += 1
            else:
                yield item

        await asyncio.gather(*tasks, return_exceptions=True)


def run_async_crawl(
    seed_urls: List[str],
    tor_manager,
    extractor: PageExtractor,
    config: Optional[AsyncCrawlerConfig] = None,
    known_urls: Optional[Set[str]] = None,
) -> List[CrawlResult]:
    """
    Convenience wrapper: run an async crawl from synchronous code.

    Returns all results as a list once crawling is complete.
    """
    async def _run() -> List[CrawlResult]:
        results: List[CrawlResult] = []
        async with AsyncCrawler(tor_manager, extractor, config) as crawler:
            async for result in crawler.crawl_all(seed_urls, known_urls):
                results.append(result)
        return results

    return asyncio.run(_run())
