"""
Prometheus metrics for DeepWebHarvester.

Exposes an HTTP /metrics endpoint (default :9090) with counters and gauges
for pages crawled, IOC counts, threat classifications, and Tor circuit renewals.

Usage::

    from deepwebharvester.metrics import Metrics, start_metrics_server
    start_metrics_server(port=9090)
    Metrics.pages_crawled.inc()
"""
from __future__ import annotations

import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from prometheus_client import (  # type: ignore[import]
        Counter,
        Gauge,
        Histogram,
        Info,
        start_http_server,
        REGISTRY,
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger.debug("prometheus_client not installed — metrics disabled.")


class _NullMetric:
    """Silent no-op when prometheus_client is not installed."""
    def inc(self, *a: object, **kw: object) -> None: ...
    def dec(self, *a: object, **kw: object) -> None: ...
    def set(self, *a: object, **kw: object) -> None: ...
    def observe(self, *a: object, **kw: object) -> None: ...
    def labels(self, **kw: object) -> "_NullMetric": return self
    def info(self, *a: object, **kw: object) -> None: ...


def _counter(name: str, doc: str, labels: Optional[list] = None):
    if not PROMETHEUS_AVAILABLE:
        return _NullMetric()
    return Counter(name, doc, labels or [])


def _gauge(name: str, doc: str, labels: Optional[list] = None):
    if not PROMETHEUS_AVAILABLE:
        return _NullMetric()
    return Gauge(name, doc, labels or [])


def _histogram(name: str, doc: str, buckets=None):
    if not PROMETHEUS_AVAILABLE:
        return _NullMetric()
    kw = {"buckets": buckets} if buckets else {}
    return Histogram(name, doc, **kw)


class Metrics:
    """Namespace for all application-level Prometheus metrics."""

    # ── Crawler ───────────────────────────────────────────────────────────────
    pages_crawled      = _counter("dwh_pages_crawled_total",
                                  "Total pages successfully crawled")
    pages_failed       = _counter("dwh_pages_failed_total",
                                  "Total pages that failed all retry attempts")
    pages_skipped      = _counter("dwh_pages_skipped_total",
                                  "Pages skipped (blacklisted or duplicate)")
    pages_deduplicated = _counter("dwh_pages_deduplicated_total",
                                  "Pages skipped due to content deduplication")
    sites_crawled      = _counter("dwh_sites_crawled_total",
                                  "Distinct .onion sites completed")
    crawl_duration     = _histogram(
        "dwh_page_crawl_duration_seconds",
        "HTTP fetch + parse duration per page",
        buckets=[1, 5, 10, 30, 60, 120],
    )

    # ── Tor ───────────────────────────────────────────────────────────────────
    circuit_renewals   = _counter("dwh_tor_circuit_renewals_total",
                                  "Number of Tor circuit renewals")
    tor_verified       = _gauge("dwh_tor_verified",
                                "1 if last Tor verification succeeded, 0 otherwise")

    # ── Intelligence ──────────────────────────────────────────────────────────
    iocs_extracted     = _counter("dwh_iocs_extracted_total",
                                  "Total IOC instances extracted", ["ioc_type"])
    threats_classified = _counter("dwh_threats_classified_total",
                                  "Pages classified by threat level", ["risk_label"])
    threat_score       = _histogram(
        "dwh_threat_risk_score",
        "Distribution of per-page risk scores",
        buckets=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    )

    # ── API ───────────────────────────────────────────────────────────────────
    api_requests       = _counter("dwh_api_requests_total",
                                  "API requests by endpoint and method",
                                  ["endpoint", "method", "status"])
    active_jobs        = _gauge("dwh_active_crawl_jobs",
                                "Number of currently running crawl jobs")

    # ── Alerts ───────────────────────────────────────────────────────────────
    alerts_sent        = _counter("dwh_alerts_sent_total",
                                  "Webhook alerts dispatched", ["risk_label"])
    alerts_failed      = _counter("dwh_alerts_failed_total",
                                  "Webhook alert delivery failures")


_server_started = False
_server_lock = threading.Lock()


def start_metrics_server(port: int = 9090, addr: str = "") -> bool:
    """
    Start the Prometheus HTTP metrics server in a background thread.

    Safe to call multiple times — subsequent calls are no-ops.

    Returns:
        True if the server started successfully, False otherwise.
    """
    global _server_started
    if not PROMETHEUS_AVAILABLE:
        logger.warning("prometheus_client not installed; metrics server not started.")
        return False
    with _server_lock:
        if _server_started:
            return True
        try:
            start_http_server(port, addr=addr)
            _server_started = True
            logger.info("Prometheus metrics server listening on %s:%d", addr or "*", port)
            return True
        except OSError as exc:
            logger.error("Could not start metrics server on port %d: %s", port, exc)
            return False
