"""
Core crawling engine.

Implements a breadth-first crawler with:
- Per-site page limits and depth limits
- Global content-hash deduplication across all sites
- Concurrent multi-site crawling via a thread pool
- Periodic Tor circuit renewal
- Exponential-backoff retry on network failures
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Set, Tuple

from requests import Session
from requests.exceptions import ConnectionError, RequestException

from .extractor import PageExtractor

logger = logging.getLogger(__name__)


# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass
class CrawlResult:
    """Structured result for a single successfully crawled page."""

    url: str
    title: str
    text: str
    content_hash: str
    depth: int
    crawl_time: float       # seconds spent fetching + parsing
    links_found: int        # count of valid .onion links extracted
    site: str               # base .onion domain


@dataclass
class CrawlStats:
    """Aggregate statistics for a crawl session."""

    sites_crawled: int = 0
    pages_crawled: int = 0
    pages_failed: int = 0
    pages_skipped: int = 0
    pages_deduplicated: int = 0
    _start_time: float = field(default_factory=time.time, repr=False)

    @property
    def elapsed(self) -> float:
        """Elapsed wall-clock seconds since the crawl began."""
        return time.time() - self._start_time


# ── Crawler ───────────────────────────────────────────────────────────────────


class Crawler:
    """
    Orchestrates BFS crawling across one or more .onion seed URLs.

    Args:
        tor_manager:         A :class:`~deepwebharvester.tor_manager.TorManager` instance.
        extractor:           A :class:`~deepwebharvester.extractor.PageExtractor` instance.
        max_depth:           Maximum link-follow depth from each seed URL.
        max_pages:           Maximum pages to collect per seed site.
        crawl_delay:         Seconds to wait between consecutive page fetches.
        request_timeout:     HTTP request timeout in seconds.
        retry_count:         Number of retry attempts before giving up on a URL.
        backoff_factor:      Sleep multiplier for exponential back-off.
        renew_circuit_every: Renew Tor circuit every N pages crawled globally.
        max_workers:         Number of concurrent site-crawl threads.
        on_page_crawled:     Optional callback invoked with each :class:`CrawlResult`.
    """

    def __init__(
        self,
        tor_manager,
        extractor: PageExtractor,
        max_depth: int = 2,
        max_pages: int = 20,
        crawl_delay: float = 7.0,
        request_timeout: int = 30,
        retry_count: int = 3,
        backoff_factor: float = 4.0,
        renew_circuit_every: int = 10,
        max_workers: int = 3,
        on_page_crawled: Optional[Callable[[CrawlResult], None]] = None,
    ) -> None:
        self._tor = tor_manager
        self._extractor = extractor
        self._max_depth = max_depth
        self._max_pages = max_pages
        self._crawl_delay = crawl_delay
        self._request_timeout = request_timeout
        self._retry_count = retry_count
        self._backoff_factor = backoff_factor
        self._renew_every = renew_circuit_every
        self._max_workers = max_workers
        self._on_page_crawled = on_page_crawled

        self._stats = CrawlStats()
        self._global_hashes: Set[str] = set()
        self._hash_lock = threading.Lock()
        self._counter_lock = threading.Lock()
        self._global_page_count = 0

    @property
    def stats(self) -> CrawlStats:
        """Read-only access to crawl statistics."""
        return self._stats

    # ── Private helpers ───────────────────────────────────────────────────────

    def _fetch(self, url: str, session: Session) -> Optional[str]:
        """
        GET *url* with exponential-backoff retries.

        Returns the response body as a string, or ``None`` if all attempts fail.
        """
        last_exc: Optional[Exception] = None
        for attempt in range(1, self._retry_count + 1):
            try:
                resp = session.get(url, timeout=self._request_timeout)
                resp.raise_for_status()
                return resp.text
            except (RequestException, ConnectionError) as exc:
                last_exc = exc
                sleep_sec = self._backoff_factor * (2 ** (attempt - 1))
                logger.warning(
                    "Attempt %d/%d for %s failed: %s — retrying in %.0fs.",
                    attempt,
                    self._retry_count,
                    url,
                    exc,
                    sleep_sec,
                )
                time.sleep(sleep_sec)
        logger.error(
            "All %d attempt(s) failed for %s: %s",
            self._retry_count,
            url,
            last_exc,
        )
        return None

    def _crawl_page(
        self, url: str, depth: int, session: Session
    ) -> Tuple[Optional[CrawlResult], List[str]]:
        """
        Fetch and parse a single page.

        Returns:
            A ``(result, links)`` tuple.  *result* is ``None`` when the page is
            blacklisted, unreachable, or a duplicate.  *links* always contains
            any .onion URLs discovered (so the BFS queue can be populated even
            when *result* is ``None``).
        """
        if self._extractor.is_blacklisted(url):
            logger.info("Skipping blacklisted path: %s", url)
            with self._counter_lock:
                self._stats.pages_skipped += 1
            return None, []

        logger.info("[depth=%d] Fetching: %s", depth, url)
        t0 = time.monotonic()
        html = self._fetch(url, session)
        if html is None:
            with self._counter_lock:
                self._stats.pages_failed += 1
            return None, []

        title, text, content_hash, links = self._extractor.extract_content(html, url)
        crawl_time = time.monotonic() - t0

        # ── Global content deduplication ──────────────────────────────────────
        with self._hash_lock:
            if content_hash in self._global_hashes:
                logger.debug("Duplicate content, skipping: %s", url)
                with self._counter_lock:
                    self._stats.pages_deduplicated += 1
                return None, links  # still propagate links
            self._global_hashes.add(content_hash)

        result = CrawlResult(
            url=url,
            title=title,
            text=text,
            content_hash=content_hash,
            depth=depth,
            crawl_time=crawl_time,
            links_found=len(links),
            site=self._extractor.get_base_domain(url),
        )
        return result, links

    def _maybe_renew_circuit(self) -> None:
        """Renew Tor circuit if the global page threshold has been reached."""
        with self._counter_lock:
            count = self._global_page_count
        if count > 0 and count % self._renew_every == 0:
            self._tor.renew_circuit()

    # ── Public interface ──────────────────────────────────────────────────────

    def crawl_site(
        self,
        start_url: str,
        known_urls: Optional[Set[str]] = None,
    ) -> List[CrawlResult]:
        """
        BFS crawl a single .onion site up to *max_depth* and *max_pages*.

        Args:
            start_url:  The seed .onion URL.
            known_urls: URLs already crawled in a previous session (resume support).

        Returns:
            A list of :class:`CrawlResult` objects for each newly crawled page.
        """
        session = self._tor.create_session()
        crawled: Set[str] = set(known_urls or set())
        queue: deque[Tuple[str, int]] = deque([(start_url, 0)])
        results: List[CrawlResult] = []
        pages_this_site = 0

        logger.info("Starting BFS crawl of: %s", start_url)

        while queue and pages_this_site < self._max_pages:
            url, depth = queue.popleft()

            if url in crawled or depth > self._max_depth:
                continue
            crawled.add(url)

            result, links = self._crawl_page(url, depth, session)

            if result:
                results.append(result)
                pages_this_site += 1
                with self._counter_lock:
                    self._stats.pages_crawled += 1
                    self._global_page_count += 1
                if self._on_page_crawled:
                    self._on_page_crawled(result)
                logger.info(
                    "  [%s] %d page(s) collected so far.", start_url, pages_this_site
                )

            # Enqueue discovered links regardless of dedup status
            if depth < self._max_depth:
                for link in links:
                    if link not in crawled:
                        queue.append((link, depth + 1))

            time.sleep(self._crawl_delay)
            self._maybe_renew_circuit()

        with self._counter_lock:
            self._stats.sites_crawled += 1

        logger.info(
            "Completed crawl of %s: %d page(s) collected.", start_url, len(results)
        )
        return results

    def crawl_all(
        self,
        seed_urls: List[str],
        known_urls: Optional[Set[str]] = None,
    ) -> List[CrawlResult]:
        """
        Crawl multiple .onion sites, optionally in parallel.

        Invalid URLs are logged and skipped.  When *max_workers* > 1 each site
        is crawled in a separate thread so slow .onion sites do not block others.

        Args:
            seed_urls:  List of seed .onion URLs.
            known_urls: Previously collected URLs to skip (resume support).

        Returns:
            Combined :class:`CrawlResult` list from all sites.
        """
        valid_urls = [u for u in seed_urls if self._extractor.is_valid_onion_url(u)]
        skipped = set(seed_urls) - set(valid_urls)
        for url in skipped:
            logger.warning("Invalid or non-.onion URL skipped: %s", url)

        if not valid_urls:
            logger.error("No valid .onion seed URLs to crawl.")
            return []

        all_results: List[CrawlResult] = []

        if self._max_workers <= 1 or len(valid_urls) == 1:
            for url in valid_urls:
                all_results.extend(self.crawl_site(url, known_urls))
        else:
            workers = min(self._max_workers, len(valid_urls))
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dwh") as pool:
                futures = {
                    pool.submit(self.crawl_site, url, known_urls): url
                    for url in valid_urls
                }
                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        all_results.extend(future.result())
                    except Exception as exc:  # noqa: BLE001
                        logger.error("Unhandled exception crawling %s: %s", url, exc)

        return all_results
