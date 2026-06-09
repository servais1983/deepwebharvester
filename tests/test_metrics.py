"""Tests for metrics.py — graceful operation with and without prometheus_client."""
import sys
import types
import importlib
import pytest


def test_null_metric_ops():
    """NullMetric silently absorbs all calls when prometheus unavailable."""
    import deepwebharvester.metrics as m
    null = m._NullMetric()
    null.inc()
    null.dec()
    null.set(1)
    null.observe(3.14)
    null.labels(foo="bar").inc()


def test_metrics_counters_exist():
    """Metrics class attributes are accessible regardless of prometheus install."""
    from deepwebharvester.metrics import Metrics
    assert hasattr(Metrics, "pages_crawled")
    assert hasattr(Metrics, "pages_failed")
    assert hasattr(Metrics, "iocs_extracted")
    assert hasattr(Metrics, "threats_classified")
    assert hasattr(Metrics, "circuit_renewals")
    assert hasattr(Metrics, "api_requests")
    assert hasattr(Metrics, "alerts_sent")


def test_start_metrics_server_without_prometheus(monkeypatch):
    """start_metrics_server returns False gracefully if prometheus_client absent."""
    import deepwebharvester.metrics as m
    monkeypatch.setattr(m, "PROMETHEUS_AVAILABLE", False)
    monkeypatch.setattr(m, "_server_started", False)
    result = m.start_metrics_server(port=19090)
    assert result is False


def test_start_metrics_server_idempotent(monkeypatch):
    """start_metrics_server is a no-op on second call."""
    import deepwebharvester.metrics as m
    monkeypatch.setattr(m, "_server_started", True)
    # Should return True without trying to bind a port
    result = m.start_metrics_server(port=19091)
    assert result is True


def test_counter_gauge_histogram_null_when_prometheus_off(monkeypatch):
    """_counter/_gauge/_histogram return NullMetric when prometheus disabled."""
    import deepwebharvester.metrics as m
    monkeypatch.setattr(m, "PROMETHEUS_AVAILABLE", False)
    c = m._counter("x_total", "x")
    g = m._gauge("y", "y")
    h = m._histogram("z", "z")
    assert isinstance(c, m._NullMetric)
    assert isinstance(g, m._NullMetric)
    assert isinstance(h, m._NullMetric)


def test_start_metrics_server_oserror(monkeypatch):
    """start_metrics_server returns False on OSError (port in use)."""
    import deepwebharvester.metrics as m
    monkeypatch.setattr(m, "PROMETHEUS_AVAILABLE", True)
    monkeypatch.setattr(m, "_server_started", False)
    import unittest.mock as mock
    with mock.patch("deepwebharvester.metrics.start_http_server",
                    side_effect=OSError("port in use")):
        result = m.start_metrics_server(port=19092)
    assert result is False


def test_start_metrics_server_success(monkeypatch):
    """start_metrics_server returns True and sets _server_started on success."""
    import deepwebharvester.metrics as m
    import unittest.mock as mock
    monkeypatch.setattr(m, "PROMETHEUS_AVAILABLE", True)
    monkeypatch.setattr(m, "_server_started", False)
    with mock.patch("deepwebharvester.metrics.start_http_server"):
        result = m.start_metrics_server(port=19093)
    assert result is True
    # reset so other tests are not affected
    monkeypatch.setattr(m, "_server_started", False)


def test_null_metric_info():
    """NullMetric.info() is a silent no-op."""
    import deepwebharvester.metrics as m
    null = m._NullMetric()
    null.info("some_info")  # must not raise


def test_metrics_extra_attrs():
    """Metrics class has all expected attributes."""
    from deepwebharvester.metrics import Metrics
    for attr in ("tor_verified", "crawl_duration", "threat_score",
                 "alerts_sent", "circuit_renewals"):
        assert hasattr(Metrics, attr)
