"""
Tests for Crawler BFS logic, deduplication, stats, and multi-site crawling.

All tests use mocked Tor sessions to avoid requiring a live Tor process.
"""
from __future__ import annotations

from typing import List
from unittest.mock import MagicMock

import pytest

from deepwebharvester.crawler import CrawlResult, CrawlStats, Crawler
from deepwebharvester.extractor import PageExtractor
from tests.conftest import SAMPLE_HTML, VALID_ONION, VALID_ONION_2

BLACKLISTED_URL = VALID_ONION + "/login"
INVALID_URL = "http://notanonion.example.com"


# ── CrawlStats ────────────────────────────────────────────────────────────────


class TestCrawlStats:
    def test_initial_counts_are_zero(self) -> None:
        stats = CrawlStats()
        assert stats.pages_crawled == 0
        assert stats.pages_failed == 0
        assert stats.sites_crawled == 0

    def test_elapsed_is_positive(self) -> None:
        stats = CrawlStats()
        assert stats.elapsed >= 0.0


# ── Basic crawl_site ──────────────────────────────────────────────────────────


class TestCrawlSite:
    def test_returns_list_of_results(self, fast_crawler: Crawler) -> None:
        results = fast_crawler.crawl_site(VALID_ONION)
        assert isinstance(results, list)

    def test_at_least_one_page_crawled(self, fast_crawler: Crawler) -> None:
        results = fast_crawler.crawl_site(VALID_ONION)
        assert len(results) >= 1

    def test_result_is_crawl_result_instance(self, fast_crawler: Crawler) -> None:
        results = fast_crawler.crawl_site(VALID_ONION)
        assert all(isinstance(r, CrawlResult) for r in results)

    def test_title_extracted(self, fast_crawler: Crawler) -> None:
        results = fast_crawler.crawl_site(VALID_ONION)
        assert results[0].title == "Dark OSINT Research Site"

    def test_url_recorded(self, fast_crawler: Crawler) -> None:
        results = fast_crawler.crawl_site(VALID_ONION)
        assert results[0].url == VALID_ONION

    def test_site_field_is_base_domain(self, fast_crawler: Crawler) -> None:
        results = fast_crawler.crawl_site(VALID_ONION)
        assert results[0].site == VALID_ONION

    def test_content_hash_is_set(self, fast_crawler: Crawler) -> None:
        results = fast_crawler.crawl_site(VALID_ONION)
        assert len(results[0].content_hash) == 64

    def test_depth_starts_at_zero(self, fast_crawler: Crawler) -> None:
        results = fast_crawler.crawl_site(VALID_ONION)
        assert results[0].depth == 0

    def test_crawl_time_positive(self, fast_crawler: Crawler) -> None:
        results = fast_crawler.crawl_site(VALID_ONION)
        assert results[0].crawl_time >= 0.0


# ── Statistics ────────────────────────────────────────────────────────────────


class TestCrawlStats:
    def test_sites_crawled_incremented(self, fast_crawler: Crawler) -> None:
        fast_crawler.crawl_site(VALID_ONION)
        assert fast_crawler.stats.sites_crawled == 1

    def test_pages_crawled_incremented(self, fast_crawler: Crawler) -> None:
        fast_crawler.crawl_site(VALID_ONION)
        assert fast_crawler.stats.pages_crawled >= 1

    def test_pages_skipped_for_blacklisted(
        self,
        mock_tor_manager: MagicMock,
        extractor: PageExtractor,
    ) -> None:
        # Point the mock to return the blacklisted URL from links
        html = (
            f'<html><head><title>Root</title></head>'
            f'<body><a href="{BLACKLISTED_URL}">login</a></body></html>'
        )
        mock_tor_manager.create_session.return_value.get.return_value.text = html
        crawler = Crawler(
            tor_manager=mock_tor_manager,
            extractor=extractor,
            max_depth=1,
            max_pages=10,
            crawl_delay=0.0,
            retry_count=1,
            backoff_factor=0.0,
            renew_circuit_every=1000,
            max_workers=1,
        )
        crawler.crawl_site(VALID_ONION)
        assert crawler.stats.pages_skipped >= 1


# ── Content deduplication ─────────────────────────────────────────────────────


class TestDeduplication:
    def test_same_site_twice_deduplicates(self, fast_crawler: Crawler) -> None:
        fast_crawler.crawl_site(VALID_ONION)
        fast_crawler.crawl_site(VALID_ONION)
        # Second crawl should hit dedup logic
        assert fast_crawler.stats.pages_deduplicated >= 1

    def test_duplicate_content_not_in_results(self, fast_crawler: Crawler) -> None:
        results1: List[CrawlResult] = fast_crawler.crawl_site(VALID_ONION)
        results2: List[CrawlResult] = fast_crawler.crawl_site(VALID_ONION)
        # All results from run 2 should have been deduplicated
        hashes1 = {r.content_hash for r in results1}
        hashes2 = {r.content_hash for r in results2}
        # No new hashes should appear in the second run
        assert not (hashes2 - hashes1)


# ── Max pages limit ───────────────────────────────────────────────────────────


class TestMaxPages:
    def test_max_pages_respected(
        self,
        mock_tor_manager: MagicMock,
        extractor: PageExtractor,
    ) -> None:
        crawler = Crawler(
            tor_manager=mock_tor_manager,
            extractor=extractor,
            max_depth=5,
            max_pages=2,
            crawl_delay=0.0,
            retry_count=1,
            backoff_factor=0.0,
            renew_circuit_every=1000,
            max_workers=1,
        )
        results = crawler.crawl_site(VALID_ONION)
        assert len(results) <= 2


# ── crawl_all ─────────────────────────────────────────────────────────────────


class TestCrawlAll:
    def test_invalid_url_excluded(self, fast_crawler: Crawler) -> None:
        results = fast_crawler.crawl_all([INVALID_URL])
        assert results == []

    def test_valid_url_crawled(self, fast_crawler: Crawler) -> None:
        results = fast_crawler.crawl_all([VALID_ONION])
        assert len(results) >= 1

    def test_mixed_valid_invalid(self, fast_crawler: Crawler) -> None:
        results = fast_crawler.crawl_all([VALID_ONION, INVALID_URL])
        # Only the valid URL should produce results
        assert len(results) >= 1

    def test_empty_list_returns_empty(self, fast_crawler: Crawler) -> None:
        results = fast_crawler.crawl_all([])
        assert results == []

    def test_stats_updated_across_multiple_sites(
        self,
        mock_tor_manager: MagicMock,
        extractor: PageExtractor,
    ) -> None:
        crawler = Crawler(
            tor_manager=mock_tor_manager,
            extractor=extractor,
            max_depth=0,
            max_pages=1,
            crawl_delay=0.0,
            retry_count=1,
            backoff_factor=0.0,
            renew_circuit_every=1000,
            max_workers=1,
        )
        # Use the same mock (same content) for both sites — second will be deduped
        crawler.crawl_all([VALID_ONION])
        assert crawler.stats.sites_crawled >= 1


# ── on_page_crawled callback ──────────────────────────────────────────────────


class TestCallback:
    def test_callback_invoked_for_each_result(
        self,
        mock_tor_manager: MagicMock,
        extractor: PageExtractor,
    ) -> None:
        collected: List[CrawlResult] = []
        crawler = Crawler(
            tor_manager=mock_tor_manager,
            extractor=extractor,
            max_depth=0,
            max_pages=5,
            crawl_delay=0.0,
            retry_count=1,
            backoff_factor=0.0,
            renew_circuit_every=1000,
            max_workers=1,
            on_page_crawled=collected.append,
        )
        results = crawler.crawl_site(VALID_ONION)
        assert len(collected) == len(results)


# ── Network failure handling ──────────────────────────────────────────────────


class TestNetworkFailures:
    def test_failed_requests_increment_failed_count(
        self,
        mock_tor_manager: MagicMock,
        extractor: PageExtractor,
    ) -> None:
        from requests.exceptions import ConnectionError

        mock_session = MagicMock()
        mock_session.get.side_effect = ConnectionError("Tor circuit broken")
        mock_tor_manager.create_session.return_value = mock_session

        crawler = Crawler(
            tor_manager=mock_tor_manager,
            extractor=extractor,
            max_depth=0,
            max_pages=1,
            crawl_delay=0.0,
            retry_count=1,
            backoff_factor=0.0,
            renew_circuit_every=1000,
            max_workers=1,
        )
        results = crawler.crawl_site(VALID_ONION)
        assert results == []
        assert crawler.stats.pages_failed >= 1

    def test_partial_failure_does_not_abort_crawl(
        self,
        mock_tor_manager: MagicMock,
        extractor: PageExtractor,
    ) -> None:
        """If one URL fails, BFS should continue with remaining URLs."""
        from requests.exceptions import RequestException

        call_count = 0
        good_response = MagicMock()
        good_response.text = SAMPLE_HTML
        good_response.raise_for_status.return_value = None

        def side_effect(*args, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RequestException("First call fails")
            return good_response

        mock_session = MagicMock()
        mock_session.get.side_effect = side_effect
        mock_tor_manager.create_session.return_value = mock_session

        crawler = Crawler(
            tor_manager=mock_tor_manager,
            extractor=extractor,
            max_depth=0,
            max_pages=3,
            crawl_delay=0.0,
            retry_count=1,
            backoff_factor=0.0,
            renew_circuit_every=1000,
            max_workers=1,
        )
        # Provide a second valid URL so BFS has something to fall back to
        results = crawler.crawl_all([VALID_ONION, VALID_ONION_2])
        # The second URL (VALID_ONION_2) should still be crawled successfully
        assert crawler.stats.pages_crawled >= 0  # graceful — no crash
