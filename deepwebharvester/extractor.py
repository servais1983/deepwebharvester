"""
HTML content extraction from .onion pages.

Provides URL validation, link harvesting, and structured text extraction
from BeautifulSoup-parsed pages.
"""
from __future__ import annotations

import hashlib
import re
from typing import List, Set, Tuple
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

# Tor v3 onion addresses use 56 base32 characters (lower-case a-z, 2-7)
_ONION_V3_RE = re.compile(r"^https?://[a-z2-7]{56}\.onion(/|$)", re.IGNORECASE)

# Tags whose content should always be discarded
_NOISE_TAGS = ["script", "style", "noscript", "head", "meta", "link"]


class PageExtractor:
    """
    Stateless helper for extracting structured data from HTML pages.

    Args:
        blacklist_paths: URL path prefixes/suffixes to skip (e.g. ``/login``).
    """

    def __init__(self, blacklist_paths: List[str] | None = None) -> None:
        self._blacklist = [p.lower().rstrip("/") for p in (blacklist_paths or [])]

    # ── URL helpers ───────────────────────────────────────────────────────────

    def is_valid_onion_url(self, url: str) -> bool:
        """Return ``True`` for valid Tor v3 .onion URLs."""
        return bool(_ONION_V3_RE.match(url))

    def is_blacklisted(self, url: str) -> bool:
        """Return ``True`` when the URL path matches a blacklisted entry."""
        path = urlparse(url).path.lower().rstrip("/")
        return any(path == bl or path.endswith(bl) for bl in self._blacklist)

    @staticmethod
    def get_base_domain(url: str) -> str:
        """Return ``scheme://netloc`` for *url*."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    # ── Extraction ────────────────────────────────────────────────────────────

    def extract_links(self, base_url: str, soup: BeautifulSoup) -> Set[str]:
        """
        Harvest all valid .onion hrefs from *soup* resolved against *base_url*.

        Args:
            base_url: The URL of the page being parsed (used to resolve relative links).
            soup:     Parsed HTML document.

        Returns:
            A set of absolute, fragment-stripped .onion URLs.
        """
        links: Set[str] = set()
        for tag in soup.find_all("a", href=True):
            href = str(tag["href"]).strip()
            if not href or href.startswith(("#", "javascript:", "mailto:")):
                continue
            full_url = urljoin(base_url, href).split("#")[0]
            if self.is_valid_onion_url(full_url):
                links.add(full_url)
        return links

    def extract_content(
        self, html: str, url: str
    ) -> Tuple[str, str, str, List[str]]:
        """
        Parse *html* and return structured page content.

        Args:
            html: Raw HTML source.
            url:  The URL this HTML was fetched from.

        Returns:
            A 4-tuple of ``(title, text, content_hash, links)`` where:

            * **title** – page ``<title>`` text or ``"No Title"``.
            * **text**  – cleaned visible body text.
            * **content_hash** – SHA-256 hex digest of *text* for deduplication.
            * **links** – list of valid .onion URLs found on the page.
        """
        soup = BeautifulSoup(html, "lxml")

        # ── Title ─────────────────────────────────────────────────────────────
        title = "No Title"
        if soup.title and soup.title.string:
            title = soup.title.string.strip()

        # ── Visible text ──────────────────────────────────────────────────────
        for tag in soup(_NOISE_TAGS):
            tag.decompose()
        raw_text = soup.get_text(separator="\n", strip=True)
        # Collapse runs of blank lines to a single blank line
        text = re.sub(r"\n{3,}", "\n\n", raw_text)

        # ── Content hash ──────────────────────────────────────────────────────
        content_hash = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

        # ── Links ─────────────────────────────────────────────────────────────
        links = list(self.extract_links(url, soup))

        return title, text, content_hash, links
