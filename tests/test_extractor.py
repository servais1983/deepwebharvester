"""
Tests for PageExtractor.

Covers URL validation, blacklist filtering, link extraction,
content parsing, and hash determinism.
"""
from __future__ import annotations

import pytest
from bs4 import BeautifulSoup

from deepwebharvester.extractor import PageExtractor
from tests.conftest import SAMPLE_HTML, VALID_ONION, VALID_ONION_2

# ── Additional test URLs ──────────────────────────────────────────────────────

SHORT_ONION = "http://tooshort.onion"
CLEAR_WEB = "https://example.com"
V2_ONION = "http://facebookcorewwwi.onion"   # v2 (16 chars) — should fail


# ── URL validation ────────────────────────────────────────────────────────────


class TestIsValidOnionUrl:
    def test_valid_v3_http(self, extractor: PageExtractor) -> None:
        assert extractor.is_valid_onion_url(VALID_ONION)

    def test_valid_v3_https(self, extractor: PageExtractor) -> None:
        url = VALID_ONION.replace("http://", "https://")
        assert extractor.is_valid_onion_url(url)

    def test_valid_v3_with_path(self, extractor: PageExtractor) -> None:
        assert extractor.is_valid_onion_url(VALID_ONION + "/some/path?q=1")

    def test_invalid_short_onion(self, extractor: PageExtractor) -> None:
        assert not extractor.is_valid_onion_url(SHORT_ONION)

    def test_invalid_v2_onion(self, extractor: PageExtractor) -> None:
        assert not extractor.is_valid_onion_url(V2_ONION)

    def test_invalid_clearweb(self, extractor: PageExtractor) -> None:
        assert not extractor.is_valid_onion_url(CLEAR_WEB)

    def test_invalid_empty(self, extractor: PageExtractor) -> None:
        assert not extractor.is_valid_onion_url("")

    def test_invalid_no_scheme(self, extractor: PageExtractor) -> None:
        address = VALID_ONION.replace("http://", "")
        assert not extractor.is_valid_onion_url(address)


# ── Blacklist filtering ───────────────────────────────────────────────────────


class TestIsBlacklisted:
    def test_exact_blacklisted_path(self, extractor: PageExtractor) -> None:
        assert extractor.is_blacklisted(VALID_ONION + "/login")

    def test_blacklisted_path_with_trailing_slash(self, extractor: PageExtractor) -> None:
        assert extractor.is_blacklisted(VALID_ONION + "/login/")

    def test_blacklisted_subpath(self, extractor: PageExtractor) -> None:
        assert extractor.is_blacklisted(VALID_ONION + "/user/signup")

    def test_non_blacklisted_path(self, extractor: PageExtractor) -> None:
        assert not extractor.is_blacklisted(VALID_ONION + "/about")

    def test_root_not_blacklisted(self, extractor: PageExtractor) -> None:
        assert not extractor.is_blacklisted(VALID_ONION + "/")

    def test_similar_but_not_blacklisted(self, extractor: PageExtractor) -> None:
        # '/logininfo' should NOT match '/login'
        assert not extractor.is_blacklisted(VALID_ONION + "/logininfo")


# ── Link extraction ───────────────────────────────────────────────────────────


class TestExtractLinks:
    def test_absolute_onion_link_included(self, extractor: PageExtractor) -> None:
        soup = BeautifulSoup(SAMPLE_HTML, "lxml")
        links = extractor.extract_links(VALID_ONION, soup)
        # SAMPLE_HTML contains a link to VALID_ONION/page2
        assert any(VALID_ONION in lnk for lnk in links)

    def test_clearweb_link_excluded(self, extractor: PageExtractor) -> None:
        soup = BeautifulSoup(SAMPLE_HTML, "lxml")
        links = extractor.extract_links(VALID_ONION, soup)
        assert not any("clearweb.example.com" in lnk for lnk in links)

    def test_relative_link_resolved(self, extractor: PageExtractor) -> None:
        # Relative links on a valid .onion page resolve to the same domain and
        # should therefore be included (56-char valid host is preserved by urljoin).
        html = f'<a href="/relative-page">rel</a>'
        soup = BeautifulSoup(html, "lxml")
        links = extractor.extract_links(VALID_ONION, soup)
        assert any("relative-page" in lnk for lnk in links)

    def test_fragment_stripped(self, extractor: PageExtractor) -> None:
        html = f'<a href="{VALID_ONION}/page#section">link</a>'
        soup = BeautifulSoup(html, "lxml")
        links = extractor.extract_links(VALID_ONION, soup)
        assert not any("#section" in lnk for lnk in links)

    def test_javascript_href_excluded(self, extractor: PageExtractor) -> None:
        html = '<a href="javascript:void(0)">js link</a>'
        soup = BeautifulSoup(html, "lxml")
        links = extractor.extract_links(VALID_ONION, soup)
        assert len(links) == 0

    def test_empty_page_returns_empty_set(self, extractor: PageExtractor) -> None:
        soup = BeautifulSoup("<html><body></body></html>", "lxml")
        links = extractor.extract_links(VALID_ONION, soup)
        assert links == set()


# ── Content extraction ────────────────────────────────────────────────────────


class TestExtractContent:
    def test_title_extracted(self, extractor: PageExtractor) -> None:
        title, _, _, _ = extractor.extract_content(SAMPLE_HTML, VALID_ONION)
        assert title == "Dark OSINT Research Site"

    def test_no_title_fallback(self, extractor: PageExtractor) -> None:
        html = "<html><body><p>No title here</p></body></html>"
        title, _, _, _ = extractor.extract_content(html, VALID_ONION)
        assert title == "No Title"

    def test_scripts_removed_from_text(self, extractor: PageExtractor) -> None:
        _, text, _, _ = extractor.extract_content(SAMPLE_HTML, VALID_ONION)
        assert "injected script" not in text

    def test_visible_text_preserved(self, extractor: PageExtractor) -> None:
        _, text, _, _ = extractor.extract_content(SAMPLE_HTML, VALID_ONION)
        assert "Legitimate research content" in text

    def test_content_hash_is_hex_string(self, extractor: PageExtractor) -> None:
        _, _, h, _ = extractor.extract_content(SAMPLE_HTML, VALID_ONION)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_content_hash_is_deterministic(self, extractor: PageExtractor) -> None:
        _, _, h1, _ = extractor.extract_content(SAMPLE_HTML, VALID_ONION)
        _, _, h2, _ = extractor.extract_content(SAMPLE_HTML, VALID_ONION)
        assert h1 == h2

    def test_different_pages_different_hashes(self, extractor: PageExtractor) -> None:
        html_a = "<html><body><p>Page A content</p></body></html>"
        html_b = "<html><body><p>Page B content — different!</p></body></html>"
        _, _, h_a, _ = extractor.extract_content(html_a, VALID_ONION)
        _, _, h_b, _ = extractor.extract_content(html_b, VALID_ONION)
        assert h_a != h_b

    def test_links_returned_as_list(self, extractor: PageExtractor) -> None:
        _, _, _, links = extractor.extract_content(SAMPLE_HTML, VALID_ONION)
        assert isinstance(links, list)


# ── Base domain ───────────────────────────────────────────────────────────────


class TestGetBaseDomain:
    def test_strips_path(self, extractor: PageExtractor) -> None:
        url = VALID_ONION + "/deep/path?q=1&r=2"
        assert extractor.get_base_domain(url) == VALID_ONION

    def test_root_unchanged(self, extractor: PageExtractor) -> None:
        assert extractor.get_base_domain(VALID_ONION) == VALID_ONION
