"""
Tests for deepwebharvester.report — HTML report generation.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from deepwebharvester.crawler import CrawlResult
from deepwebharvester.report import ReportGenerator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(
    url: str = "http://" + "a" * 56 + ".onion/",
    site: str = "http://" + "a" * 56 + ".onion",
    title: str = "Test Page",
    text: str = "malware ransomware trojan keylogger",
    depth: int = 0,
    crawl_time: float = 1.0,
    links_found: int = 5,
    content_hash: str = "a" * 64,
) -> CrawlResult:
    return CrawlResult(
        url=url,
        site=site,
        title=title,
        text=text,
        depth=depth,
        crawl_time=crawl_time,
        links_found=links_found,
        content_hash=content_hash,
    )


# ---------------------------------------------------------------------------
# ReportGenerator.generate()
# ---------------------------------------------------------------------------

class TestReportGeneratorGenerate:
    def test_creates_output_file(self, tmp_path):
        gen = ReportGenerator()
        results = [_make_result()]
        path = gen.generate(results, output_dir=str(tmp_path))
        assert path.exists()

    def test_returns_path_object(self, tmp_path):
        gen = ReportGenerator()
        path = gen.generate([_make_result()], output_dir=str(tmp_path))
        assert isinstance(path, Path)

    def test_default_filename_is_timestamped(self, tmp_path):
        gen = ReportGenerator()
        path = gen.generate([_make_result()], output_dir=str(tmp_path))
        assert path.name.startswith("report_")
        assert path.suffix == ".html"

    def test_custom_filename(self, tmp_path):
        gen = ReportGenerator()
        path = gen.generate(
            [_make_result()],
            output_dir=str(tmp_path),
            filename="custom_report.html",
        )
        assert path.name == "custom_report.html"

    def test_output_dir_created(self, tmp_path):
        nested = tmp_path / "sub" / "dir"
        gen = ReportGenerator()
        path = gen.generate([_make_result()], output_dir=str(nested))
        assert nested.exists()
        assert path.exists()

    def test_empty_results(self, tmp_path):
        gen = ReportGenerator()
        path = gen.generate([], output_dir=str(tmp_path))
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_multiple_results(self, tmp_path):
        gen = ReportGenerator()
        results = [
            _make_result(url="http://" + "a" * 56 + ".onion/page1"),
            _make_result(url="http://" + "a" * 56 + ".onion/page2"),
            _make_result(
                url="http://" + "b" * 56 + ".onion/",
                site="http://" + "b" * 56 + ".onion",
            ),
        ]
        path = gen.generate(results, output_dir=str(tmp_path))
        assert path.exists()


# ---------------------------------------------------------------------------
# HTML content validation
# ---------------------------------------------------------------------------

class TestReportHTMLContent:
    @pytest.fixture()
    def html(self, tmp_path) -> str:
        gen = ReportGenerator()
        path = gen.generate([_make_result()], output_dir=str(tmp_path))
        return path.read_text(encoding="utf-8")

    def test_valid_html_doctype(self, html):
        assert html.startswith("<!DOCTYPE html>")

    def test_charset_utf8(self, html):
        assert 'charset="UTF-8"' in html

    def test_title_present(self, html):
        assert "<title>" in html
        assert "DeepWebHarvester" in html

    def test_css_embedded(self, html):
        assert "<style>" in html
        # Ensure no external CDN references
        assert "cdn." not in html.lower()
        assert "googleapis.com" not in html

    def test_executive_summary_section(self, html):
        assert "Executive Summary" in html

    def test_risk_distribution_section(self, html):
        assert "Risk Distribution" in html

    def test_ioc_registry_section(self, html):
        assert "IOC Registry" in html

    def test_high_risk_pages_section(self, html):
        assert "High-Risk Pages" in html

    def test_site_breakdown_section(self, html):
        assert "Site Breakdown" in html

    def test_url_index_section(self, html):
        assert "Crawled URL Index" in html

    def test_footer_present(self, html):
        assert "authorized cybersecurity" in html.lower()

    def test_version_in_header(self, html):
        from deepwebharvester import __version__
        assert __version__ in html

    def test_result_url_in_index(self, html):
        assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in html


# ---------------------------------------------------------------------------
# Risk label rendering
# ---------------------------------------------------------------------------

class TestReportRiskLabels:
    def test_high_risk_page_appears_in_high_risk_section(self, tmp_path):
        # Lots of malware keywords → should produce High or Critical risk
        result = _make_result(
            text="malware ransomware trojan botnet keylogger exploit payload " * 100,
            title="Malware C2 Panel",
        )
        gen = ReportGenerator()
        path = gen.generate([result], output_dir=str(tmp_path))
        html = path.read_text(encoding="utf-8")
        # High or Critical badge should appear
        assert "risk-High" in html or "risk-Critical" in html

    def test_low_risk_page_labelled_low(self, tmp_path):
        result = _make_result(text="Hello world, this is an innocent page.")
        gen = ReportGenerator()
        path = gen.generate([result], output_dir=str(tmp_path))
        html = path.read_text(encoding="utf-8")
        assert "risk-Low" in html

    def test_no_javascript_in_report(self, tmp_path):
        gen = ReportGenerator()
        path = gen.generate([_make_result()], output_dir=str(tmp_path))
        html = path.read_text(encoding="utf-8")
        assert "<script" not in html.lower()


# ---------------------------------------------------------------------------
# IOC content in report
# ---------------------------------------------------------------------------

class TestReportIOCContent:
    def test_ipv4_appears_in_ioc_registry(self, tmp_path):
        result = _make_result(text="C2 server at 203.0.113.99 running nginx")
        gen = ReportGenerator()
        path = gen.generate([result], output_dir=str(tmp_path))
        html = path.read_text(encoding="utf-8")
        assert "203.0.113.99" in html

    def test_cve_appears_in_ioc_registry(self, tmp_path):
        result = _make_result(text="Exploit CVE-2023-44487 using this payload")
        gen = ReportGenerator()
        path = gen.generate([result], output_dir=str(tmp_path))
        html = path.read_text(encoding="utf-8")
        assert "CVE-2023-44487" in html

    def test_email_appears_in_ioc_registry(self, tmp_path):
        result = _make_result(text="Contact evil@malware.com for the service")
        gen = ReportGenerator()
        path = gen.generate([result], output_dir=str(tmp_path))
        html = path.read_text(encoding="utf-8")
        assert "evil@malware.com" in html

    def test_html_entities_escaped(self, tmp_path):
        # Title with angle brackets must be HTML-escaped
        result = _make_result(title="<script>alert(1)</script>")
        gen = ReportGenerator()
        path = gen.generate([result], output_dir=str(tmp_path))
        html = path.read_text(encoding="utf-8")
        # The raw script tag should not appear — only its escaped form
        assert "<script>alert(1)</script>" not in html
