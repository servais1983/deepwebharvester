"""
Webhook alert system for high-severity threat findings.

Sends structured JSON alerts to configured endpoints (Slack, Teams, generic HTTP)
when a crawled page scores High or Critical on the threat classifier.

Configuration via environment variables::

    DWH_ALERT_WEBHOOKS=https://hooks.slack.com/services/...,https://other-endpoint/
    DWH_ALERT_MIN_RISK=High    # Low | Medium | High | Critical
    DWH_ALERT_TIMEOUT=10
    DWH_SLACK_WEBHOOK=https://hooks.slack.com/services/...  (convenience alias)
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests

from .crawler import CrawlResult
from .intelligence import PageIntelligence, ThreatAssessment
from .metrics import Metrics

logger = logging.getLogger(__name__)

_RISK_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


@dataclass
class AlertConfig:
    """Alert delivery configuration."""
    webhook_urls: List[str]
    min_risk_label: str = "High"   # only alert at this level and above
    timeout: int = 10              # HTTP request timeout in seconds
    retry_count: int = 2
    include_text_preview: bool = True
    text_preview_chars: int = 300


def load_alert_config() -> AlertConfig:
    """Build AlertConfig from environment variables."""
    raw_urls = os.getenv("DWH_ALERT_WEBHOOKS", "")
    slack_url = os.getenv("DWH_SLACK_WEBHOOK", "")

    urls: List[str] = []
    if raw_urls:
        urls.extend(u.strip() for u in raw_urls.split(",") if u.strip())
    if slack_url and slack_url not in urls:
        urls.append(slack_url)

    return AlertConfig(
        webhook_urls=urls,
        min_risk_label=os.getenv("DWH_ALERT_MIN_RISK", "High"),
        timeout=int(os.getenv("DWH_ALERT_TIMEOUT", "10")),
        retry_count=int(os.getenv("DWH_ALERT_RETRY", "2")),
    )


class AlertDispatcher:
    """
    Dispatches webhook alerts when threat classification exceeds a threshold.

    Usage::

        dispatcher = AlertDispatcher(load_alert_config())
        dispatcher.evaluate_and_alert(result, intel)
    """

    def __init__(self, config: Optional[AlertConfig] = None) -> None:
        self._cfg = config or load_alert_config()
        self._min_rank = _RISK_ORDER.get(self._cfg.min_risk_label, 2)
        if not self._cfg.webhook_urls:
            logger.info("No alert webhook URLs configured — alerts disabled.")

    def _should_alert(self, threat: ThreatAssessment) -> bool:
        rank = _RISK_ORDER.get(threat.risk_label, 0)
        return rank >= self._min_rank

    def _build_payload(
        self, result: CrawlResult, intel: PageIntelligence
    ) -> Dict:
        """Build a structured JSON payload (Slack-compatible)."""
        threat = intel.threat
        iocs = intel.iocs
        color = {"Low": "#36a64f", "Medium": "#FFA500",
                 "High": "#FF4500", "Critical": "#FF0000"}.get(
            threat.risk_label, "#cccccc"
        )

        text_preview = ""
        if self._cfg.include_text_preview and result.text:
            text_preview = result.text[: self._cfg.text_preview_chars]
            if len(result.text) > self._cfg.text_preview_chars:
                text_preview += "…"

        # Slack Block Kit + generic fallback
        payload: Dict = {
            "text": (
                f":rotating_light: [{threat.risk_label}] "
                f"Dark web threat detected — {result.site}"
            ),
            "attachments": [
                {
                    "color": color,
                    "title": result.title or result.url,
                    "title_link": result.url,
                    "fields": [
                        {"title": "Risk Score", "value": str(threat.risk_score),
                         "short": True},
                        {"title": "Risk Label", "value": threat.risk_label,
                         "short": True},
                        {"title": "Categories",
                         "value": ", ".join(threat.categories) or "N/A",
                         "short": False},
                        {"title": "IOC Count",
                         "value": str(iocs.total), "short": True},
                        {"title": "Site",
                         "value": result.site, "short": True},
                    ],
                    "footer": "DeepWebHarvester v2",
                    "ts": int(time.time()),
                }
            ],
            "dwh_alert": {   # machine-readable section for generic endpoints
                "url": result.url,
                "site": result.site,
                "risk_label": threat.risk_label,
                "risk_score": threat.risk_score,
                "categories": threat.categories,
                "ioc_count": iocs.total,
                "btc_addresses": iocs.btc_addresses[:5],
                "cves": iocs.cves[:10],
                "text_preview": text_preview,
            },
        }
        return payload

    def _send(self, webhook_url: str, payload: Dict) -> bool:
        """POST payload to a single webhook URL, with retries."""
        for attempt in range(1, self._cfg.retry_count + 1):
            try:
                resp = requests.post(
                    webhook_url,
                    json=payload,
                    timeout=self._cfg.timeout,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                logger.info("Alert sent to %s (HTTP %d)", webhook_url, resp.status_code)
                Metrics.alerts_sent.labels(
                    risk_label=payload.get("dwh_alert", {}).get("risk_label", "?")
                ).inc()
                return True
            except requests.RequestException as exc:
                logger.warning(
                    "Alert delivery attempt %d/%d to %s failed: %s",
                    attempt, self._cfg.retry_count, webhook_url, exc,
                )
        logger.error("Alert delivery failed after %d attempts to %s",
                     self._cfg.retry_count, webhook_url)
        Metrics.alerts_failed.inc()
        return False

    def evaluate_and_alert(
        self, result: CrawlResult, intel: PageIntelligence
    ) -> int:
        """
        Evaluate threat level and dispatch alerts if threshold is met.

        Args:
            result: The crawled page result.
            intel:  Intelligence analysis for the page.

        Returns:
            Number of webhooks successfully notified.
        """
        if not self._cfg.webhook_urls:
            return 0
        if not self._should_alert(intel.threat):
            return 0

        payload = self._build_payload(result, intel)
        sent = sum(
            1 for url in self._cfg.webhook_urls if self._send(url, payload)
        )
        if sent:
            logger.info(
                "Alert dispatched for %s (risk=%s) to %d/%d webhooks",
                result.url,
                intel.threat.risk_label,
                sent,
                len(self._cfg.webhook_urls),
            )
        return sent
