"""Tests for stix_exporter.py — STIX 2.1 bundle generation."""
import json
import os
import tempfile
import pytest

try:
    import stix2
    from deepwebharvester.stix_exporter import STIXExporter, _get_identity
    STIX_AVAILABLE = True
except ImportError:
    STIX_AVAILABLE = False

from deepwebharvester.crawler import CrawlResult
from deepwebharvester.intelligence import (
    IntelligenceExtractor,
    PageIntelligence,
    IOCs,
    ThreatAssessment,
)

pytestmark = pytest.mark.skipif(not STIX_AVAILABLE, reason="stix2 not installed")


def _result(url="http://abc.onion/") -> CrawlResult:
    return CrawlResult(
        url=url, title="Dark Market", text="buy sell credentials password bitcoin",
        content_hash="aabbcc", depth=0, crawl_time=2.0,
        links_found=3, site="http://abc.onion",
    )


def _intel(risk_label="High") -> PageIntelligence:
    return PageIntelligence(
        url="http://abc.onion/",
        iocs=IOCs(
            ipv4=["8.8.8.8"],
            domains=["evil.com"],
            btc_addresses=["1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"],
            xmr_addresses=["4" + "A" * 94],
            cves=["CVE-2024-1234"],
            urls=["http://evil.com/path"],
        ),
        threat=ThreatAssessment(
            categories=["Financial Fraud"],
            risk_score=8.0,
            risk_label=risk_label,
        ),
    )


class TestSTIXExporter:
    @pytest.fixture
    def exporter(self):
        return STIXExporter()

    def test_build_bundle_returns_bundle(self, exporter):
        bundle = exporter.build_bundle([_result()], [_intel()])
        assert isinstance(bundle, stix2.Bundle)

    def test_bundle_contains_identity(self, exporter):
        bundle = exporter.build_bundle([_result()], [_intel()])
        types = {obj.type for obj in bundle.objects}
        assert "identity" in types

    def test_bundle_contains_indicators(self, exporter):
        bundle = exporter.build_bundle([_result()], [_intel()])
        types = [obj.type for obj in bundle.objects]
        assert "indicator" in types

    def test_bundle_contains_report(self, exporter):
        bundle = exporter.build_bundle([_result()], [_intel()], job_id="job-1")
        types = [obj.type for obj in bundle.objects]
        assert "report" in types

    def test_bundle_min_risk_filter(self, exporter):
        low_intel = _intel(risk_label="Low")
        bundle = exporter.build_bundle([_result()], [low_intel],
                                        min_risk_label="High")
        # Only identity, no indicators for low-risk page
        types = [obj.type for obj in bundle.objects]
        assert "indicator" not in types

    def test_to_json_is_valid_json(self, exporter):
        bundle = exporter.build_bundle([_result()], [_intel()])
        js = STIXExporter.to_json(bundle)
        parsed = json.loads(js)
        assert parsed["type"] == "bundle"

    def test_save_writes_file(self, exporter, tmp_path):
        bundle = exporter.build_bundle([_result()], [_intel()])
        out = str(tmp_path / "test.stix.json")
        STIXExporter.save(bundle, out)
        assert os.path.exists(out)
        with open(out) as f:
            data = json.load(f)
        assert data["type"] == "bundle"

    def test_vulnerability_included_for_cve(self, exporter):
        bundle = exporter.build_bundle([_result()], [_intel()])
        types = [obj.type for obj in bundle.objects]
        assert "vulnerability" in types

    def test_no_stix_raises_import_error(self, monkeypatch):
        import deepwebharvester.stix_exporter as m
        monkeypatch.setattr(m, "STIX_AVAILABLE", False)
        with pytest.raises(ImportError):
            STIXExporter()
