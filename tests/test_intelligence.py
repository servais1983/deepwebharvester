"""
Tests for deepwebharvester.intelligence — IOC extraction and threat
classification.
"""
from __future__ import annotations

import pytest

from deepwebharvester.intelligence import (
    IntelligenceExtractor,
    IOCs,
    PageIntelligence,
    ThreatAssessment,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def extractor() -> IntelligenceExtractor:
    return IntelligenceExtractor()


# ---------------------------------------------------------------------------
# IOCs dataclass
# ---------------------------------------------------------------------------

class TestIOCsDataclass:
    def test_total_empty(self):
        iocs = IOCs()
        assert iocs.total == 0

    def test_total_counts_all_fields(self):
        iocs = IOCs(
            ipv4=["1.2.3.4"],
            emails=["a@b.com"],
            md5=["a" * 32],
            sha1=["b" * 40],
            sha256=["c" * 64],
            cves=["CVE-2023-0001"],
            btc_addresses=["1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf"],
            xmr_addresses=["4" + "A" * 94],
            onion_addresses=["a" * 56 + ".onion"],
            domains=["example.com"],
            urls=["https://example.com/path"],
            pgp_present=True,
        )
        # pgp_present is bool, not counted in total
        assert iocs.total == 11

    def test_as_dict_keys(self):
        iocs = IOCs()
        d = iocs.as_dict()
        expected_keys = {
            "ipv4", "emails", "md5", "sha1", "sha256", "cves",
            "btc_addresses", "xmr_addresses", "onion_addresses",
            "domains", "urls", "pgp_present", "total",
        }
        assert set(d.keys()) == expected_keys

    def test_as_dict_total(self):
        iocs = IOCs(ipv4=["1.2.3.4", "5.6.7.8"])
        d = iocs.as_dict()
        assert d["total"] == 2

    def test_as_dict_urls_capped_at_20(self):
        urls = [f"https://example.com/{i}" for i in range(30)]
        iocs = IOCs(urls=urls)
        d = iocs.as_dict()
        assert len(d["urls"]) == 20

    def test_as_dict_pgp_present_false(self):
        iocs = IOCs()
        assert iocs.as_dict()["pgp_present"] is False


# ---------------------------------------------------------------------------
# ThreatAssessment dataclass
# ---------------------------------------------------------------------------

class TestThreatAssessmentDataclass:
    def test_defaults(self):
        ta = ThreatAssessment()
        assert ta.risk_score == 0.0
        assert ta.risk_label == "Low"
        assert ta.categories == []
        assert ta.keyword_hits == {}

    def test_as_dict_keys(self):
        ta = ThreatAssessment()
        assert set(ta.as_dict().keys()) == {
            "categories", "risk_score", "risk_label", "keyword_hits"
        }

    def test_as_dict_values(self):
        ta = ThreatAssessment(
            categories=["Malware & Ransomware"],
            risk_score=8.5,
            risk_label="High",
            keyword_hits={"Malware & Ransomware": 10},
        )
        d = ta.as_dict()
        assert d["risk_label"] == "High"
        assert d["risk_score"] == 8.5


# ---------------------------------------------------------------------------
# IOC extraction — extract_iocs()
# ---------------------------------------------------------------------------

class TestExtractIOCsIPv4:
    def test_public_ipv4_detected(self, extractor):
        iocs = extractor.extract_iocs("C2 server at 203.0.113.5 running nginx")
        assert "203.0.113.5" in iocs.ipv4

    def test_private_ipv4_excluded(self, extractor):
        text = "Internal: 10.0.0.1 192.168.1.1 127.0.0.1 172.16.0.1"
        iocs = extractor.extract_iocs(text)
        # Only 172.16.0.1 is not in the _PRIVATE_PREFIXES list
        assert "10.0.0.1" not in iocs.ipv4
        assert "192.168.1.1" not in iocs.ipv4
        assert "127.0.0.1" not in iocs.ipv4

    def test_loopback_excluded(self, extractor):
        iocs = extractor.extract_iocs("Connect to 127.0.0.1:8080")
        assert "127.0.0.1" not in iocs.ipv4

    def test_multiple_ips_deduplicated(self, extractor):
        iocs = extractor.extract_iocs("8.8.8.8 and 8.8.8.8 again")
        assert iocs.ipv4.count("8.8.8.8") == 1

    def test_ipv4_sorted(self, extractor):
        iocs = extractor.extract_iocs("Seen: 203.0.113.10 and 1.1.1.1")
        assert iocs.ipv4 == sorted(iocs.ipv4)


class TestExtractIOCsEmail:
    def test_email_detected(self, extractor):
        iocs = extractor.extract_iocs("contact admin@darkforum.onion for support")
        assert "admin@darkforum.onion" in iocs.emails

    def test_standard_email(self, extractor):
        iocs = extractor.extract_iocs("reach us at user.name+tag@example.co.uk")
        assert "user.name+tag@example.co.uk" in iocs.emails

    def test_emails_deduplicated(self, extractor):
        iocs = extractor.extract_iocs("evil@bad.com evil@bad.com")
        assert iocs.emails.count("evil@bad.com") == 1


class TestExtractIOCsHashes:
    def test_md5_detected(self, extractor):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        iocs = extractor.extract_iocs(f"Hash: {md5}")
        assert md5 in iocs.md5

    def test_sha1_detected(self, extractor):
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        iocs = extractor.extract_iocs(f"SHA1: {sha1}")
        assert sha1 in iocs.sha1

    def test_sha256_detected(self, extractor):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        iocs = extractor.extract_iocs(f"SHA256: {sha256}")
        assert sha256 in iocs.sha256

    def test_hashes_deduplicated(self, extractor):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        iocs = extractor.extract_iocs(f"{md5} {md5}")
        assert iocs.md5.count(md5) == 1


class TestExtractIOCsCVE:
    def test_cve_detected(self, extractor):
        iocs = extractor.extract_iocs("Exploiting CVE-2023-44487 (HTTP/2 Rapid Reset)")
        assert "CVE-2023-44487" in iocs.cves

    def test_cve_normalised_uppercase(self, extractor):
        iocs = extractor.extract_iocs("cve-2021-44228 log4shell")
        assert "CVE-2021-44228" in iocs.cves

    def test_multiple_cves(self, extractor):
        iocs = extractor.extract_iocs("CVE-2021-44228 and CVE-2022-0001")
        assert len(iocs.cves) == 2

    def test_cve_deduplicated(self, extractor):
        iocs = extractor.extract_iocs("CVE-2021-1234 CVE-2021-1234")
        assert iocs.cves.count("CVE-2021-1234") == 1


class TestExtractIOCsBitcoin:
    def test_legacy_btc_detected(self, extractor):
        # P2PKH address (starts with 1)
        addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfna"
        iocs = extractor.extract_iocs(f"Send to {addr}")
        assert addr in iocs.btc_addresses

    def test_p2sh_btc_detected(self, extractor):
        # P2SH address (starts with 3)
        addr = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
        iocs = extractor.extract_iocs(f"Wallet: {addr}")
        assert addr in iocs.btc_addresses


class TestExtractIOCsOnion:
    def test_v3_onion_detected(self, extractor):
        onion = "a" * 56 + ".onion"
        iocs = extractor.extract_iocs(f"Visit {onion}")
        assert onion in iocs.onion_addresses

    def test_onion_case_insensitive(self, extractor):
        onion = "a" * 56 + ".ONION"
        iocs = extractor.extract_iocs(f"Visit {onion}")
        assert onion.lower() in [o.lower() for o in iocs.onion_addresses]

    def test_short_onion_not_matched(self, extractor):
        # Only 52 chars — too short for v3
        onion = "a" * 52 + ".onion"
        iocs = extractor.extract_iocs(f"Visit {onion}")
        assert onion not in iocs.onion_addresses


class TestExtractIOCsURL:
    def test_https_url_detected(self, extractor):
        iocs = extractor.extract_iocs("Download from https://malware.example.com/payload.exe")
        assert any("malware.example.com" in u for u in iocs.urls)

    def test_http_url_detected(self, extractor):
        iocs = extractor.extract_iocs("See http://example.com/path?q=1")
        assert any("example.com" in u for u in iocs.urls)

    def test_urls_capped_at_50(self, extractor):
        text = " ".join(f"https://example.com/page{i}" for i in range(60))
        iocs = extractor.extract_iocs(text)
        assert len(iocs.urls) <= 50


class TestExtractIOCsPGP:
    def test_pgp_block_detected(self, extractor):
        text = "Here is my key: -----BEGIN PGP PUBLIC KEY BLOCK-----"
        iocs = extractor.extract_iocs(text)
        assert iocs.pgp_present is True

    def test_no_pgp(self, extractor):
        iocs = extractor.extract_iocs("No key here")
        assert iocs.pgp_present is False


class TestExtractIOCsEmpty:
    def test_empty_string(self, extractor):
        iocs = extractor.extract_iocs("")
        assert iocs.total == 0
        assert iocs.pgp_present is False

    def test_whitespace_only(self, extractor):
        iocs = extractor.extract_iocs("   \n\t  ")
        assert iocs.total == 0


# ---------------------------------------------------------------------------
# Threat classification — classify_threat()
# ---------------------------------------------------------------------------

class TestClassifyThreatEmpty:
    def test_empty_text_returns_low(self, extractor):
        ta = extractor.classify_threat("")
        assert ta.risk_label == "Low"
        assert ta.risk_score == 0.0
        assert ta.categories == []

    def test_irrelevant_text_returns_low(self, extractor):
        ta = extractor.classify_threat("The quick brown fox jumps over the lazy dog.")
        assert ta.risk_label == "Low"


class TestClassifyThreatCategories:
    def test_malware_category_detected(self, extractor):
        text = " ".join(["malware", "ransomware", "trojan", "botnet"] * 10)
        ta = extractor.classify_threat(text)
        assert "Malware & Ransomware" in ta.categories

    def test_financial_fraud_detected(self, extractor):
        text = " ".join(["credit card", "cvv", "carding", "cashout"] * 10)
        ta = extractor.classify_threat(text)
        assert "Financial Fraud" in ta.categories

    def test_hacking_services_detected(self, extractor):
        text = " ".join(["ddos", "exploit kit", "zero-day", "web shell"] * 10)
        ta = extractor.classify_threat(text)
        assert "Hacking Services" in ta.categories

    def test_credentials_detected(self, extractor):
        text = " ".join(["password", "credentials", "login", "leaked", "breach"] * 10)
        ta = extractor.classify_threat(text)
        assert "Credentials & Leaks" in ta.categories

    def test_keyword_hits_recorded(self, extractor):
        text = "malware malware ransomware"
        ta = extractor.classify_threat(text)
        assert "Malware & Ransomware" in ta.keyword_hits
        assert ta.keyword_hits["Malware & Ransomware"] >= 3

    def test_categories_ordered_by_score(self, extractor):
        # Malware keywords are heavily weighted; mix in low-weight forum terms
        text = ("malware ransomware trojan botnet keylogger exploit " * 20
                + "forum thread post " * 2)
        ta = extractor.classify_threat(text)
        if len(ta.categories) >= 2:
            # Malware should outrank Forum
            assert ta.categories[0] != "Forum & Community"


class TestClassifyThreatRiskLabels:
    def _make_text(self, keyword: str, repeat: int = 200) -> str:
        return (keyword + " ") * repeat

    def test_low_label(self, extractor):
        # Single malware keyword in a long text → very low keyword density
        # 1 hit in 5000 words: density = 1/(5000/1000) = 0.2 → score ≈ 1.9 (Low)
        filler = "the quick brown fox jumps over the lazy dog " * 500
        ta = extractor.classify_threat("malware " + filler)
        assert ta.risk_label in ("Low", "Medium")

    def test_critical_label_high_density(self, extractor):
        # Very dense malware text → should hit Critical or High
        text = "malware ransomware " * 300
        ta = extractor.classify_threat(text)
        assert ta.risk_label in ("High", "Critical")

    def test_risk_score_bounds(self, extractor):
        text = "malware ransomware trojan botnet keylogger " * 200
        ta = extractor.classify_threat(text)
        assert 0.0 <= ta.risk_score <= 10.0


# ---------------------------------------------------------------------------
# Combined analysis — analyze()
# ---------------------------------------------------------------------------

class TestAnalyze:
    def test_returns_page_intelligence(self, extractor):
        result = extractor.analyze("http://test.onion/", "malware ransomware 8.8.8.8")
        assert isinstance(result, PageIntelligence)

    def test_url_preserved(self, extractor):
        url = "http://example.onion/page"
        result = extractor.analyze(url, "some text")
        assert result.url == url

    def test_iocs_populated(self, extractor):
        text = "contact us at evil@bad.com or 203.0.113.5"
        result = extractor.analyze("http://test.onion/", text)
        assert "evil@bad.com" in result.iocs.emails
        assert "203.0.113.5" in result.iocs.ipv4

    def test_threat_populated(self, extractor):
        text = "malware ransomware trojan keylogger botnet " * 50
        result = extractor.analyze("http://test.onion/", text)
        assert result.threat.risk_label in ("Medium", "High", "Critical")

    def test_as_dict_structure(self, extractor):
        result = extractor.analyze("http://test.onion/", "hello world")
        d = result.as_dict()
        assert set(d.keys()) == {"url", "iocs", "threat"}
        assert isinstance(d["iocs"], dict)
        assert isinstance(d["threat"], dict)
