"""
Tests for TorManager.

Uses mocks to avoid requiring a live Tor process during CI.
Controller-related tests are skipped when stem's C extensions are
unavailable (e.g. missing _cffi_backend in sandboxed environments).
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from deepwebharvester.tor_manager import TorManager

# stem.control requires the cryptography C extension (_cffi_backend).
# Check for it without actually importing stem.control (which may panic).
try:
    import _cffi_backend as _  # noqa: F401
    _STEM_AVAILABLE = True
except ImportError:
    _STEM_AVAILABLE = False

_skip_stem = pytest.mark.skipif(
    not _STEM_AVAILABLE,
    reason="stem.control unavailable (cryptography C extension not functional)",
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def manager() -> TorManager:
    return TorManager(
        socks_host="127.0.0.1",
        socks_port=9050,
        control_host="127.0.0.1",
        control_port=9051,
        control_password="test_password_123",
        user_agent="DeepWebHarvester/2.0 (test)",
    )


# ── proxy_url ─────────────────────────────────────────────────────────────────


class TestProxyUrl:
    def test_socks5h_scheme(self, manager: TorManager) -> None:
        assert manager.proxy_url.startswith("socks5h://")

    def test_contains_host_and_port(self, manager: TorManager) -> None:
        assert "127.0.0.1:9050" in manager.proxy_url

    def test_custom_port(self) -> None:
        m = TorManager(socks_port=19050)
        assert "19050" in m.proxy_url


# ── create_session ────────────────────────────────────────────────────────────


class TestCreateSession:
    def test_returns_requests_session(self, manager: TorManager) -> None:
        session = manager.create_session()
        assert isinstance(session, requests.Session)

    def test_http_proxy_set(self, manager: TorManager) -> None:
        session = manager.create_session()
        assert "http" in session.proxies

    def test_https_proxy_set(self, manager: TorManager) -> None:
        session = manager.create_session()
        assert "https" in session.proxies

    def test_proxies_use_socks5h(self, manager: TorManager) -> None:
        session = manager.create_session()
        assert "socks5h" in session.proxies["http"]

    def test_user_agent_header(self, manager: TorManager) -> None:
        session = manager.create_session()
        assert session.headers["User-Agent"] == "DeepWebHarvester/2.0 (test)"

    def test_dnt_header_present(self, manager: TorManager) -> None:
        session = manager.create_session()
        assert session.headers.get("DNT") == "1"

    def test_each_call_returns_new_session(self, manager: TorManager) -> None:
        s1 = manager.create_session()
        s2 = manager.create_session()
        assert s1 is not s2


# ── renew_circuit ─────────────────────────────────────────────────────────────


class TestRenewCircuit:
    def test_no_password_returns_false(self) -> None:
        m = TorManager(control_password="")
        assert m.renew_circuit() is False

    def test_no_password_does_not_invoke_stem(self) -> None:
        """When no password is set, stem should never be imported/called."""
        m = TorManager(control_password="")
        result = m.renew_circuit()
        assert result is False

    @_skip_stem
    @patch("stem.control.Controller")
    @patch("deepwebharvester.tor_manager.time.sleep", return_value=None)
    def test_successful_renewal_returns_true(
        self, _sleep: MagicMock, mock_cls: MagicMock, manager: TorManager
    ) -> None:
        mock_ctrl = MagicMock()
        mock_cls.from_port.return_value.__enter__.return_value = mock_ctrl
        result = manager.renew_circuit()
        assert result is True

    @_skip_stem
    @patch("stem.control.Controller")
    @patch("deepwebharvester.tor_manager.time.sleep", return_value=None)
    def test_signal_newnym_sent(
        self, _sleep: MagicMock, mock_cls: MagicMock, manager: TorManager
    ) -> None:
        import stem as _stem
        mock_ctrl = MagicMock()
        mock_cls.from_port.return_value.__enter__.return_value = mock_ctrl
        manager.renew_circuit()
        mock_ctrl.signal.assert_called_once_with(_stem.Signal.NEWNYM)

    @_skip_stem
    @patch("stem.control.Controller")
    @patch("deepwebharvester.tor_manager.time.sleep", return_value=None)
    def test_authentication_called(
        self, _sleep: MagicMock, mock_cls: MagicMock, manager: TorManager
    ) -> None:
        mock_ctrl = MagicMock()
        mock_cls.from_port.return_value.__enter__.return_value = mock_ctrl
        manager.renew_circuit()
        mock_ctrl.authenticate.assert_called_once_with(password="test_password_123")

    @_skip_stem
    @patch("stem.control.Controller")
    def test_exception_returns_false(
        self, mock_cls: MagicMock, manager: TorManager
    ) -> None:
        mock_cls.from_port.side_effect = ConnectionRefusedError("Tor not running")
        assert manager.renew_circuit() is False

    @_skip_stem
    @patch("stem.control.Controller")
    @patch("deepwebharvester.tor_manager.time.sleep", return_value=None)
    def test_circuits_renewed_counter(
        self, _sleep: MagicMock, mock_cls: MagicMock, manager: TorManager
    ) -> None:
        mock_ctrl = MagicMock()
        mock_cls.from_port.return_value.__enter__.return_value = mock_ctrl
        manager.renew_circuit()
        manager.renew_circuit()
        assert manager._circuits_renewed == 2


# ── verify_connection ─────────────────────────────────────────────────────────


class TestVerifyConnection:
    def test_is_tor_returns_true(self, manager: TorManager) -> None:
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {"IsTor": True, "IP": "1.2.3.4"}
        mock_session.get.return_value = mock_response
        manager.create_session = lambda: mock_session  # type: ignore
        assert manager.verify_connection() is True

    def test_not_tor_returns_false(self, manager: TorManager) -> None:
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {"IsTor": False, "IP": "1.2.3.4"}
        mock_session.get.return_value = mock_response
        manager.create_session = lambda: mock_session  # type: ignore
        assert manager.verify_connection() is False

    def test_network_error_returns_false(self, manager: TorManager) -> None:
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("network error")
        manager.create_session = lambda: mock_session  # type: ignore
        assert manager.verify_connection() is False
