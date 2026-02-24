"""
Threat intelligence extraction and content classification.

Extracts Indicators of Compromise (IOCs) from raw page text and classifies
content into threat intelligence categories with an automated risk score.
This module is fully standalone — it has no dependencies on other
DeepWebHarvester modules and can be used independently.

Typical usage::

    extractor = IntelligenceExtractor()
    iocs      = extractor.extract_iocs(page_text)
    threat    = extractor.classify_threat(page_text)
    summary   = extractor.analyze(url, page_text)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List

# ---------------------------------------------------------------------------
# Compiled IOC patterns
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)
_MD5_RE    = re.compile(r"\b[0-9a-fA-F]{32}\b")
_SHA1_RE   = re.compile(r"\b[0-9a-fA-F]{40}\b")
_SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
_CVE_RE    = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
# Bitcoin — Legacy (P2PKH/P2SH) and SegWit bech32
_BTC_RE = re.compile(
    r"\b(?:bc1[ac-hj-np-z02-9]{6,87}"
    r"|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"
)
# Monero — 95-character address starting with 4
_XMR_RE    = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
# Tor v3 onion hostnames (without scheme)
_ONION_RE  = re.compile(r"\b[a-z2-7]{56}\.onion\b", re.IGNORECASE)
# Clear-web domains (common TLDs only to reduce noise)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)"
    r"+(?:com|net|org|io|ru|cn|de|uk|fr|it|es|gov|edu|mil|co)\b",
    re.IGNORECASE,
)
# PGP blocks
_PGP_RE = re.compile(r"-----BEGIN PGP")
# Generic HTTP(S) URLs
_URL_RE = re.compile(r"https?://[^\s\"'<>]{8,200}", re.IGNORECASE)
# Private / RFC-1918 prefixes to exclude from IPv4 IOCs
_PRIVATE_PREFIXES = ("127.", "10.", "192.168.", "169.254.", "::1")


# ---------------------------------------------------------------------------
# Threat classification knowledge base
# ---------------------------------------------------------------------------

_CATEGORIES: Dict[str, List[str]] = {
    "Credentials & Leaks": [
        "password", "credentials", "login", "username", "leaked", "breach",
        "database dump", "combo list", "fullz", "account", "shell access",
        "rdp", "ssh login", "ftp", "vpn access", "admin panel",
    ],
    "Marketplace": [
        "buy", "sell", "price", "vendor", "shipping", "escrow", "market",
        "shop", "store", "listing", "order", "payment", "wallet", "checkout",
        "in stock", "out of stock", "delivery",
    ],
    "Malware & Ransomware": [
        "malware", "ransomware", "trojan", "botnet", "keylogger", "exploit",
        "payload", "c2", "command and control", "dropper", "cryptolocker",
        "ransom", "decrypt", "encryption key", "rat ", "loader", "stealer",
        "infostealer", "spyware",
    ],
    "Financial Fraud": [
        "credit card", "cvv", "carding", "dump", "bin", "cashout",
        "money laundering", "bank account", "wire transfer", "western union",
        "paypal", "swift", "iban", "routing number", "skimmer",
        "counterfeit", "fake bills",
    ],
    "Illicit Substances": [
        "cocaine", "heroin", "fentanyl", "mdma", "methamphetamine",
        "cannabis", "weed", "lsd", "ketamine", "opioid", "pills",
        "narcotics", "stimulant", "psychedelic", "benzodiazepine",
    ],
    "Hacking Services": [
        "ddos", "dos attack", "hack for hire", "zero-day", "0day",
        "vulnerability", "cve-", "exploit kit", "stresser", "booter",
        "spear phishing", "social engineering", "remote access",
        "web shell", "privilege escalation",
    ],
    "Identity Documents": [
        "passport", "id card", "driver license", "ssn", "social security",
        "birth certificate", "kyc bypass", "identity", "national id",
        "residence permit", "visa", "scan", "fake id",
    ],
    "Forum & Community": [
        "forum", "thread", "reply", "post", "member", "moderator",
        "register", "join", "discussion", "topic", "board", "community",
    ],
    "Cryptocurrency Services": [
        "mixer", "tumbler", "coin swap", "monero", "privacy coin",
        "exchange", "no kyc", "anonymous transfer", "clean btc",
        "crypto laundry",
    ],
}

# Risk weight per category (0 – 1, multiplied by keyword density to get 0–10)
_CATEGORY_RISK: Dict[str, float] = {
    "Credentials & Leaks":      0.85,
    "Marketplace":              0.55,
    "Malware & Ransomware":     0.95,
    "Financial Fraud":          0.90,
    "Illicit Substances":       0.80,
    "Hacking Services":         0.90,
    "Identity Documents":       0.85,
    "Forum & Community":        0.20,
    "Cryptocurrency Services":  0.70,
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class IOCs:
    """
    Indicators of Compromise extracted from a single page.

    All list fields contain deduplicated, sorted values.
    """

    ipv4: List[str]           = field(default_factory=list)
    emails: List[str]         = field(default_factory=list)
    md5: List[str]            = field(default_factory=list)
    sha1: List[str]           = field(default_factory=list)
    sha256: List[str]         = field(default_factory=list)
    cves: List[str]           = field(default_factory=list)
    btc_addresses: List[str]  = field(default_factory=list)
    xmr_addresses: List[str]  = field(default_factory=list)
    onion_addresses: List[str]= field(default_factory=list)
    domains: List[str]        = field(default_factory=list)
    urls: List[str]           = field(default_factory=list)
    pgp_present: bool         = False

    @property
    def total(self) -> int:
        """Total number of distinct IOC values."""
        return (
            len(self.ipv4) + len(self.emails) + len(self.md5)
            + len(self.sha1) + len(self.sha256) + len(self.cves)
            + len(self.btc_addresses) + len(self.xmr_addresses)
            + len(self.onion_addresses) + len(self.domains)
            + len(self.urls)
        )

    def as_dict(self) -> dict:
        return {
            "ipv4":           self.ipv4,
            "emails":         self.emails,
            "md5":            self.md5,
            "sha1":           self.sha1,
            "sha256":         self.sha256,
            "cves":           self.cves,
            "btc_addresses":  self.btc_addresses,
            "xmr_addresses":  self.xmr_addresses,
            "onion_addresses":self.onion_addresses,
            "domains":        self.domains,
            "urls":           self.urls[:20],   # keep serialised output concise
            "pgp_present":    self.pgp_present,
            "total":          self.total,
        }


@dataclass
class ThreatAssessment:
    """
    Threat classification and risk score for a single page.

    Attributes:
        categories:    Threat categories detected (ordered by relevance).
        risk_score:    Aggregate risk score in [0.0, 10.0].
        risk_label:    Human-readable label — Low / Medium / High / Critical.
        keyword_hits:  Number of matching keywords per category.
    """

    categories:    List[str]       = field(default_factory=list)
    risk_score:    float           = 0.0
    risk_label:    str             = "Low"
    keyword_hits:  Dict[str, int]  = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "categories":   self.categories,
            "risk_score":   self.risk_score,
            "risk_label":   self.risk_label,
            "keyword_hits": self.keyword_hits,
        }


@dataclass
class PageIntelligence:
    """Combined intelligence report for a single crawled page."""

    url:    str
    iocs:   IOCs
    threat: ThreatAssessment

    def as_dict(self) -> dict:
        return {
            "url":    self.url,
            "iocs":   self.iocs.as_dict(),
            "threat": self.threat.as_dict(),
        }


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------

class IntelligenceExtractor:
    """
    Stateless IOC extractor and threat classifier.

    All methods accept raw page text (``str``) and return structured
    dataclass instances.  The class holds no per-call state so a single
    instance can be shared across threads safely.
    """

    # ── IOC extraction ────────────────────────────────────────────────────────

    def extract_iocs(self, text: str) -> IOCs:
        """
        Extract and deduplicate all IOC types from *text*.

        Private / RFC-1918 IP addresses are excluded from results.
        The URL list is capped at 50 entries to avoid bloating storage.

        Args:
            text: Raw visible page text.

        Returns:
            A populated :class:`IOCs` instance.
        """
        ipv4_raw = set(_IPV4_RE.findall(text))
        ipv4_clean = sorted(
            ip for ip in ipv4_raw
            if not any(ip.startswith(p) for p in _PRIVATE_PREFIXES)
        )

        return IOCs(
            ipv4=ipv4_clean,
            emails=sorted(set(_EMAIL_RE.findall(text))),
            md5=sorted(set(_MD5_RE.findall(text))),
            sha1=sorted(set(_SHA1_RE.findall(text))),
            sha256=sorted(set(_SHA256_RE.findall(text))),
            cves=sorted({m.upper() for m in _CVE_RE.findall(text)}),
            btc_addresses=sorted(set(_BTC_RE.findall(text))),
            xmr_addresses=sorted(set(_XMR_RE.findall(text))),
            onion_addresses=sorted(set(_ONION_RE.findall(text))),
            domains=sorted(set(_DOMAIN_RE.findall(text))),
            urls=sorted(set(_URL_RE.findall(text)))[:50],
            pgp_present=bool(_PGP_RE.search(text)),
        )

    # ── Threat classification ─────────────────────────────────────────────────

    def classify_threat(self, text: str) -> ThreatAssessment:
        """
        Classify *text* into threat intelligence categories.

        Each category score is computed as::

            score = keyword_density_per_1000_words × category_risk_weight × 10

        The final risk score is the maximum individual category score, capped
        at 10.0.  Categories scoring above 1.0 are included in the output.

        Risk labels:
            - ``Low``      0.0 – 3.9
            - ``Medium``   4.0 – 6.9
            - ``High``     7.0 – 8.9
            - ``Critical`` 9.0 – 10.0

        Args:
            text: Raw visible page text.

        Returns:
            A populated :class:`ThreatAssessment` instance.
        """
        text_lower = text.lower()
        word_count = max(len(text_lower.split()), 1)
        category_scores: Dict[str, float] = {}
        keyword_hits: Dict[str, int] = {}

        for category, keywords in _CATEGORIES.items():
            hits = sum(text_lower.count(kw.lower()) for kw in keywords)
            if hits == 0:
                continue
            density = min(hits / (word_count / 1000.0), 1.0)
            weight  = _CATEGORY_RISK.get(category, 0.5)
            category_scores[category] = density * weight * 10.0
            keyword_hits[category] = hits

        if not category_scores:
            return ThreatAssessment(risk_label="Low")

        # Keep only categories that scored meaningfully
        sorted_cats = sorted(
            category_scores.items(), key=lambda x: x[1], reverse=True
        )
        top_cats = [cat for cat, score in sorted_cats if score > 1.0]
        risk = min(max(category_scores.values()), 10.0)

        label: str
        if risk >= 9.0:
            label = "Critical"
        elif risk >= 7.0:
            label = "High"
        elif risk >= 4.0:
            label = "Medium"
        else:
            label = "Low"

        return ThreatAssessment(
            categories=top_cats,
            risk_score=round(risk, 2),
            risk_label=label,
            keyword_hits=keyword_hits,
        )

    # ── Combined analysis ─────────────────────────────────────────────────────

    def analyze(self, url: str, text: str) -> PageIntelligence:
        """
        Run full IOC extraction and threat classification for a single page.

        Args:
            url:  The URL of the crawled page.
            text: Raw visible page text.

        Returns:
            A :class:`PageIntelligence` instance combining both analyses.
        """
        return PageIntelligence(
            url=url,
            iocs=self.extract_iocs(text),
            threat=self.classify_threat(text),
        )
