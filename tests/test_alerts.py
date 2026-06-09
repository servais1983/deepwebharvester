"""Tests for alerts.py — AlertDispatcher and config loading."""
import os
import pytest
from unittest.mock import MagicMock, patch

from deepwebharvester.alerts import (
    AlertConfig,
    AlertDispatcher,
    load_alert_config,
    _RISK_ORDER,
)
from deepwebharvester.crawler import CrawlResult
from deepwebharvester.intelligence import (
    PageIntelligence,
    IOCs,
    ThreatAssessment,
)


def _make_result(url="http://abc.onion/") -> CrawlResult:
    return CrawlResult(
        url=url, title="Test", text="content",
        content_hash="abc", depth=0, crawl_time=1.0,
        links_found=0, site="http://abc.onion",
    )


def _make_intel(risk_label="High", risk_score=8.0, categories=None) -> PageIntelligence:
    return PageIntelligence(
        url="http://abc.onion/",
        iocs=IOCs(btc_addresses=["1A2B3C"], cves=["CVE-2024-1234"]),
        threat=ThreatAssessment(
            categories=categories or ["Malware & Ransomware"],
            risk_score=risk_score,
            risk_label=risk_label,
        ),
    )


class TestAlertConfig:
    def test_load_from_env(self, monkeypatch):
        monkeypatch.setenv("DWH_ALERT_WEBHOOKS", "http://hook1,http://hook2")
        monkeypatch.setenv("DWH_ALERT_MIN_RISK", "Critical")
        cfg = load_alert_config()
        assert "http://hook1" in cfg.webhook_urls
        assert "http://hook2" in cfg.webhook_urls
        assert cfg.min_risk_label == "Critical"

    def test_slack_convenience_alias(self, monkeypatch):
        monkeypatch.setenv("DWH_SLACK_WEBHOOK", "https://hooks.slack.com/abc")
        monkeypatch.delenv("DWH_ALERT_WEBHOOKS", raising=False)
        cfg = load_alert_config()
        assert "https://hooks.slack.com/abc" in cfg.webhook_urls

    def test_no_webhooks_by_default(self, monkeypatch):
        monkeypatch.delenv("DWH_ALERT_WEBHOOKS", raising=False)
        monkeypatch.delenv("DWH_SLACK_WEBHOOK", raising=False)
        cfg = load_alert_config()
        assert cfg.webhook_urls == []


class TestAlertDispatcher:
    def _dispatcher(self, webhooks=None, min_risk="High"):
        cfg = AlertConfig(
            webhook_urls=webhooks or ["http://fake-webhook/"],
            min_risk_label=min_risk,
        )
        return AlertDispatcher(config=cfg)

    def test_no_alert_for_low_risk(self):
        d = self._dispatcher(min_risk="High")
        result = _make_result()
        intel = _make_intel(risk_label="Low", risk_score=1.0)
        assert d.evaluate_and_alert(result, intel) == 0

    def test_no_alert_for_medium_when_threshold_high(self):
        d = self._dispatcher(min_risk="High")
        intel = _make_intel(risk_label="Medium", risk_score=5.0)
        assert d.evaluate_and_alert(_make_result(), intel) == 0

    def test_alert_for_critical(self):
        d = self._dispatcher(webhooks=["http://hook/"], min_risk="High")
        intel = _make_intel(risk_label="Critical", risk_score=9.5)
        with patch("deepwebharvester.alerts.requests.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_post.return_value = mock_resp
            sent = d.evaluate_and_alert(_make_result(), intel)
        assert sent == 1
        mock_post.assert_called_once()

    def test_no_webhooks_returns_zero(self):
        cfg = AlertConfig(webhook_urls=[], min_risk_label="Low")
        d = AlertDispatcher(config=cfg)
        assert d.evaluate_and_alert(_make_result(), _make_intel()) == 0

    def test_retry_on_failure(self):
        d = self._dispatcher(webhooks=["http://hook/"])
        intel = _make_intel(risk_label="High")
        with patch("deepwebharvester.alerts.requests.post",
                   side_effect=__import__("requests").RequestException("connection refused")):
            sent = d.evaluate_and_alert(_make_result(), intel)
        assert sent == 0

    def test_payload_contains_expected_fields(self):
        d = self._dispatcher()
        result = _make_result()
        intel = _make_intel(risk_label="Critical")
        payload = d._build_payload(result, intel)
        assert "dwh_alert" in payload
        alert = payload["dwh_alert"]
        assert alert["risk_label"] == "Critical"
        assert alert["site"] == result.site
        assert "btc_addresses" in alert
